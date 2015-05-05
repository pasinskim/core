/*
   Copyright (C) CFEngine AS

   This file is part of CFEngine 3 - written and maintained by CFEngine AS.

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA

  To the extent this program is licensed as part of the Enterprise
  versions of CFEngine, the applicable Commercial Open Source License
  (COSL) may apply to this file if you as a licensee so wish it. See
  included file COSL.txt.
*/

#include <packages-wrapper.h>
#include <pipes.h>
#include <signals.h>
#include <buffer.h>
#include <ornaments.h>
#include <string_lib.h>
#include <actuator.h>
#include <file_lib.h>
#include <known_dirs.h>
#include <locks.h>

static
void LogPackagePromiseError(PackageError *error)
{
    if (error)
    {
        if (error->message && error->type)
        {
            Log(LOG_LEVEL_ERR, "have error: %s [%s]", error->type, error->message);
            free(error->message);
            free(error->type);
        }
        else if (error->type)
        {
            Log(LOG_LEVEL_ERR, "have error: %s", error->type);
            free(error->type);
        }
    }
}

static
void ParseAndLogErrorMessage(const Rlist *data)
{
    for (const Rlist *rp = data; rp != NULL; rp = rp->next)
    {
        char *line = RlistScalarValue(rp);
                   
        if (StringStartsWith(line, "Error="))
        {
            Log(LOG_LEVEL_ERR, "have error: %s", line + strlen("Error="));
        }
        else if (StringStartsWith(line, "ErrorMessage="))
        {
            Log(LOG_LEVEL_ERR, "have error message: %s", line + strlen("ErrorMessage="));
        }
        else
        {
            Log(LOG_LEVEL_ERR, "unsupported error info: %s", line);
        }
    }
}

static 
int IsReadWriteReady(const IOData *io, int timeout_sec)
{
    fd_set  rset;
    FD_ZERO(&rset);
    FD_SET(io->read_fd, &rset);

    struct timeval tv = {
        .tv_sec = timeout_sec,
        .tv_usec = 0,
    };

    int ret = select(io->read_fd + 1, &rset, NULL, NULL, &tv);

    if(ret < 0)
    {
        Log(LOG_LEVEL_ERR, "Failed checking for data. (select: %s)", GetErrorStr());
        return -1;
    }

    else if (FD_ISSET(io->read_fd, &rset))
    {
        return io->read_fd;
    }

    /* We have reached timeout */
    if(ret == 0)
    {
        Log(LOG_LEVEL_ERR, "Reading from package manager wrapper timeout");
        return 0;
    }

    Log(LOG_LEVEL_ERR,
        "Unknown outcome (ret > 0 but our only fds are not set). (select: %s)",
        GetErrorStr());

    return -1;
}

Rlist *RedDataFromPackageScript(const IOData *io)
{
    char buff[CF_BUFSIZE] = {0};
    int red_data_size = 0;
    
    Buffer *data = BufferNew();
    if (!data)
    {
        Log(LOG_LEVEL_ERR, 
            "unable to allocate buffer for handling script responses");
        return NULL;
    }
    
    int timeout_seconds_left = PACKAGE_PROMISE_SCRIPT_TIMEOUT_SEC;
    
    while(!IsPendingTermination() && timeout_seconds_left > 0)
    {
        int fd = IsReadWriteReady(io, PACKAGE_PROMISE_TERMINATION_CHECK_SEC);
        
        if (fd < 0)
        {
            Log(LOG_LEVEL_ERR, 
                "error reading data from package wrapper script: %s",
                GetErrorStr());
            return NULL;
        }
        else if (fd == io->read_fd)
        {
            ssize_t res = read(fd, buff, sizeof(buff) - 1);
            if (res == -1)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                else
                {
                    Log(LOG_LEVEL_ERR,
                        "Unable to read output from package wrapper: %s",
                        GetErrorStr());
                    BufferDestroy(data);
                    return NULL;
                }
            }
            else if (res == 0) /* reached EOF */
            {
                break;
            }
            Log(LOG_LEVEL_ERR, "red: %zu [%s]", res, buff);
            red_data_size += res;

            BufferAppendString(data, buff);
            memset(buff, 0, sizeof(buff));
        }
        else if (fd == 0) /* timeout */
        {
            timeout_seconds_left -= PACKAGE_PROMISE_TERMINATION_CHECK_SEC;
            continue;
        }
    }
    
    char *red_string = BufferClose(data);
    Rlist *response_lines = RlistFromSplitString(red_string, '\n');
    free(red_string);
    
    return response_lines;
}

int WriteScriptData(const char *data, const IOData *io)
{
    if (strlen(data) == 0)
    {
        return 0;
    }
    
    ssize_t wrt = write(io->write_fd, data, strlen(data));
    
    return wrt;
}

int WriteDataToPackageScript(const char *args, const char *data,
                             const PackageManagerWrapper *wrapper)
{
    char *command = StringFormat("%s %s", wrapper->path, args);
    IOData io = cf_popen_full_duplex(command, false);
    free(command);
    
    if (io.write_fd == 0 || io.read_fd == 0)
    {
        Log(LOG_LEVEL_VERBOSE, "some error occurred while communicating "
                "package manager script");
        return -1;
    }
    
    int res = 0;
    if (WriteScriptData(data, &io) != strlen(data))
    {
        res = -1;
    }
    
    /* If script returns non 0 status */
    if (cf_pclose_full_duplex(&io) != EXIT_SUCCESS)
    {
        Log(LOG_LEVEL_VERBOSE,
            "package manager script returned with failure");
        res = -1;
    }
    return res;
}

/* In some cases the response is expected to be not filled out. Some requests
   will have response filled only in case of errors. */
static
int ReadWriteDataToPackageScript(const char *args, const char *request,
        Rlist **response, const PackageManagerWrapper *wrapper)
{
    assert(args && request && wrapper);
    
    char *command = StringFormat("%s %s", wrapper->path, args);
    IOData io = cf_popen_full_duplex(command, true);
    free(command);
    
    if (io.write_fd == 0 || io.read_fd == 0)
    {
        Log(LOG_LEVEL_VERBOSE, "some error occurred while communicating "
                "package manager script");
        return -1;
    }
    
    if (WriteScriptData(request, &io) != strlen(request))
    {
        Log(LOG_LEVEL_ERR, "couldn't write whole data to script");
        return -1;
    }
    
    /* We can have some error message here. */
    Rlist *res = RedDataFromPackageScript(&io);
    
    /* If script returns non 0 status */
    if (cf_pclose_full_duplex(&io) != EXIT_SUCCESS)
    {
        Log(LOG_LEVEL_VERBOSE,
            "package manager script returned with failure");
        RlistDestroy(res);
        return -1;
    }
    
    *response = res;
    return 0;
}

static 
int NegotiateSupportedAPIVersion(PackageManagerWrapper *wrapper)
{
    int api_version = -1;

    Rlist *response = NULL;
    if (ReadWriteDataToPackageScript("supports-api-version", "",
            &response, wrapper) != 0)
    {
        Log(LOG_LEVEL_ERR, "Some error occurred while communicating with "
                "wrapper.");
        return -1;
    }
    
    if (response)
    {
        if (RlistLen(response) == 1)
        {
            api_version = atoi(RlistScalarValue(response));
            Log(LOG_LEVEL_ERR, "package wrapper API version: %d", api_version);
        }
        RlistDestroy(response);
    }
    return api_version;
}

static
char *ParseOptions(Rlist *options)
{
    if (RlistIsNullList(options))
    {
        return SafeStringDuplicate("");
    }
    
    Buffer *data = BufferNew();
    for (Rlist *rp = options; rp != NULL; rp = rp->next)
    {
        char *value = RlistScalarValue(rp);
        BufferAppendString(data, "options=");
        BufferAppendString(data, value);
        BufferAppendString(data, "\n");
    }
    return BufferClose(data);
}

static
void FreePackageInfo(void *item)
{
    PackageInfo *package_info = (PackageInfo*)item;
    if (package_info)
    {
        free((void*)package_info->arch);
        free((void*)package_info->name);
        free((void*)package_info->version);

        free(package_info);
    }
}

static
PackageInfo *ParseAndCheckPackageDataReply(const Rlist *data, 
                                   PackageError *error)
{
    PackageInfo * package_data = xcalloc(1, sizeof(PackageInfo));
    
    for (const Rlist *rp = data; rp != NULL; rp = rp->next)
    {
        char *line = RlistScalarValue(rp);
                   
        if (StringStartsWith(line, "PackageType="))
        {
            char *type = line + strlen("PackageType=");
            if (StringSafeEqual(type, "file"))
            {
                package_data->type = PACKAGE_TYPE_FILE;
            }
            else if (StringSafeEqual(type, "repo"))
            {
                package_data->type = PACKAGE_TYPE_REPO;
            }
            else
            {
                Log(LOG_LEVEL_ERR, "unsupported package type: %s", type);
                return NULL;
            }
        }
        else if (StringStartsWith(line, "Name="))
        {
            /* Name is mandatory for all cases. */
            
            package_data->name = 
                SafeStringDuplicate(line + strlen("Name="));
        }
        else if (StringStartsWith(line, "Version="))
        {
            if (package_data->version)
            {
                /* Some error occurred as we already have version for 
                 * given package. */
                Log(LOG_LEVEL_ERR, "duplicated package version recevied for"
                        "package: %s version: %s", package_data->name,
                        package_data->version);
                continue;
            }
            package_data->version = 
                SafeStringDuplicate(line + strlen("Version="));
        }
        else if (StringStartsWith(line, "Architecture="))
        {
            if (package_data->arch)
            {
                /* Some error occurred as we already have arch for 
                 * given package. */
                Log(LOG_LEVEL_ERR, "duplicated package arch recevied for"
                        "package: %s arch: %s", package_data->name,
                        package_data->arch);
                continue;
            }
            package_data->arch = 
                SafeStringDuplicate(line + strlen("Architecture="));
        }
        /* For handling errors */
        else if (StringStartsWith(line, "Error="))
        {
            error->type = 
                SafeStringDuplicate(line + strlen("Error="));
        }
        else if (StringStartsWith(line, "ErrorMessage="))
        {
            error->message = 
                SafeStringDuplicate(line + strlen("ErrorMessage="));
        }
        else
        {
            Log(LOG_LEVEL_ERR, "unsupported option: %s", line);
        }
    }
    
    return package_data;
}

/* IMPORTANT: this might not return all the data we need like version
              or architecture but package name MUST be known. */
static
PackageInfo *GetPackageData(const char *name, Rlist *options,
                            const PackageManagerWrapper *wrapper, 
                            PackageError *error)
{   
    char *options_str = ParseOptions(options);
    char *request = StringFormat("%sFile=%s\n", options_str, name);
    
    Rlist *response = NULL;
    if (ReadWriteDataToPackageScript("get-package-data", request, &response,
            wrapper) != 0)
    {
        Log(LOG_LEVEL_ERR, "Some error occurred while communicating with "
                "wrapper.");
        free(options_str);
        free(request);
        return NULL;
    }
    
    PackageInfo *package_data = NULL;
    
    if (response)
    {   
        package_data = ParseAndCheckPackageDataReply(response, error);
        RlistDestroy(response);
        
        if (package_data)
        {
            /* We can have only one entry at the moment. */
            /* At this point at least package name MUST be known (if no error) */
            if (!package_data->name || package_data->type == PACKAGE_TYPE_NONE)
            {
                Log(LOG_LEVEL_ERR, "can not figure out package name");
                FreePackageInfo(package_data);
                package_data = NULL;
            }
            
        }
    }
    free(options_str);
    free(request);
        
    return package_data;
}

static
char *GetPackageWrapperRealPath(const char *package_manager_name)
{
    
    //return StringFormat("%s%c%s%c%s", GetWorkDir(), FILE_SEPARATOR, "package_managers",
    //        FILE_SEPARATOR, package_manager_name);
    return SafeStringDuplicate("/tmp/dummy");
}

static
void FreePackageManageWrapper(PackageManagerWrapper *wrapper)
{
    free(wrapper->path);
    free(wrapper->name);
    free(wrapper);
}

static
PackageManagerWrapper *GetPackageManagerWrapper(const char *package_manager_name)
{
    //TODO: add cache where managers are already initialized from previous runs
    PackageManagerWrapper *wrapper = malloc(sizeof(PackageManagerWrapper));
    
    if (!wrapper)
    {
        return NULL;
    }
    
    wrapper->path = GetPackageWrapperRealPath(package_manager_name);
    wrapper->name = SafeStringDuplicate(package_manager_name);
    
    /* Check if file exists */
    struct stat sb;
    if (!wrapper->path || (stat(wrapper->path, &sb) != 0))
    {
        Log(LOG_LEVEL_VERBOSE,
            "can not find package wrapper in provided location: %s",
            wrapper->path);
        FreePackageManageWrapper(wrapper);
        return NULL;
    }
    
    /* Negotiate API version */
    wrapper->supported_api_version = NegotiateSupportedAPIVersion(wrapper);
    if (wrapper->supported_api_version != 1)
    {
        Log(LOG_LEVEL_ERR,
            "unsupported package manager wrapper API version: %d",
            wrapper->supported_api_version);
        FreePackageManageWrapper(wrapper);
        return NULL;
    }
    
    return wrapper;
}

static
int IsPackageInCache(const char *pm_name, const char *name, const char *arch,
                      const char *ver)
{
    assert(pm_name);
    
    const char *version = ver;
    /* Handle latest version in specific way for repo packages. 
     * Please note that for file packages 'latest' version is not supported
     * and check against that is made elsewhere. */
    if (version && StringSafeEqual(version, "latest"))
    {
        version = NULL;
    }
    
    CF_DB *db_cached;
    if (!OpenSubDB(&db_cached, dbid_packages_installed, pm_name))
    {
        return -1;
    }
    
    char *key = NULL;
    if (version && arch)
    {
        key = StringFormat("N<%s>V<%s>A<%s>", name, version, arch);
    }
    else if (version)
    {
        key = StringFormat("N<%s>V<%s>", name, version);
    }
    else if (arch)
    {
        key = StringFormat("N<%s>A<%s>", name, arch);
    }
    
    int is_in_cache = 0;
    char buff[1];
    if (ReadDB(db_cached, key, buff, 1))
    {
        /* Just make sure DB is not corrupted. */
        if (buff[0] == 1)
        {
            is_in_cache = 1;
        }
        else
        {
            is_in_cache = -1;
        }
    }
    
    CloseDB(db_cached);
    
    return is_in_cache;
}

void WritePackageDataToDB(CF_DB *db_installed,
        const char *name, const char *ver, const char *arch,
        UpdateType type)
{
    char package_key[strlen(name) + strlen(ver) +
                     strlen(arch) + 10];
    
    xsnprintf(package_key, sizeof(package_key),
              "N<%s>", name);
    if (type == UPDATE_TYPE_UPDATES && 
            HasKeyDB(db_installed, package_key, strlen(package_key)))
    {
        size_t val_size =
                ValueSizeDB(db_installed, package_key, strlen(package_key));
        char buff[val_size + strlen(arch) + strlen(ver) + 7];
        
        ReadDB(db_installed, package_key, buff, val_size);
        xsnprintf(buff + val_size, sizeof(package_key), "A<%s>V<%s>\n", arch, ver);
        WriteDB(db_installed, package_key, buff, sizeof(buff));
    }
    else if (type == UPDATE_TYPE_UPDATES)
    {
        char buff[strlen(arch) + strlen(ver) + 7];
        xsnprintf(buff, sizeof(package_key), "A<%s>V<%s>\n", arch, ver);
        WriteDB(db_installed, package_key, buff, sizeof(buff));
    }
    else /* UPDATE_TYPE_INSTALLED */
    {
        WriteDB(db_installed, package_key, "1", 1);
        xsnprintf(package_key, sizeof (package_key),
                "N<%s>V<%s>", name, ver);
        WriteDB(db_installed, package_key, "1", 1);
        xsnprintf(package_key, sizeof (package_key),
                "N<%s>A<%s>", name, arch);
        WriteDB(db_installed, package_key, "1", 1);
        xsnprintf(package_key, sizeof (package_key),
                "N<%s>V<%s>A<%s>", name, ver, arch);
        WriteDB(db_installed, package_key, "1", 1);
    }
}

int UpdatePackagesDB(Rlist *data, const char *pm_name, UpdateType type)
{
    assert(pm_name);
    
    PackageError error = {0};
    CF_DB *db_cached;
    dbid db_id = type == UPDATE_TYPE_INSTALLED ? dbid_packages_installed :
                                                 dbid_packages_updates;
    
    if (OpenSubDB(&db_cached, db_id, pm_name))
    {
        /* Clean db opens read transaction in case when lmdb is used. Make sure
           that emptying db is locked while using alternate db. */
        CleanDB(db_cached);

        char *package_data[3] = {NULL, NULL, NULL};

        for (const Rlist *rp = data; rp != NULL; rp = rp->next)
        {
            char *line = RlistScalarValue(rp);

            if (StringStartsWith(line, "Name="))
            {
                /* We have all the information we need from previous loop
                 * iteration. */
                if (package_data[0] && package_data[1] && package_data[2])
                {
                    WritePackageDataToDB(db_cached, package_data[0],
                                         package_data[1], package_data[2], type);
                    
                    //TODO: add list of all packages for inventory

                    package_data[1] = NULL;
                    package_data[2] = NULL;
                }
                else if (package_data[0] && (!package_data[1] || !package_data[2]))
                {
                    /* some error occurred */
                    Log(LOG_LEVEL_ERR, "Malformed response from package manager"
                            " for package %s", package_data[0]);
                }

                /* This must be the first entry on a list */
                package_data[0] = line + strlen("Name=");

            }
            else if (StringStartsWith(line, "Version="))
            {
                package_data[1] = line + strlen("Version=");
            }
            else if (StringStartsWith(line, "Architecture="))
            {
                package_data[2] = line + strlen("Architecture=");
            }
            else if (StringStartsWith(line, "Error="))
            {
                error.type = SafeStringDuplicate(line + strlen("Error="));
            }
            else if (StringStartsWith(line, "ErrorMessage="))
            {
                error.message =
                        SafeStringDuplicate(line + strlen("ErrorMessage="));
                LogPackagePromiseError(&error);
            }
        }
        /* We have one more entry left. */
        if (package_data[0] && package_data[1] && package_data[2])
        {
            WritePackageDataToDB(db_cached, package_data[0],
                             package_data[1], package_data[2], type);
        }
        
        CloseDB(db_cached);
        return 0;
    }
    /* Unable to open database. */
    return -1;
}


bool UpdateCache(Rlist* options, const PackageManagerWrapper *wrapper,
                 UpdateType type)
{
    char *options_str = ParseOptions(options);
    Rlist *response = NULL;
    if (ReadWriteDataToPackageScript("list-installed", options_str, &response,
            wrapper) != 0)
    {
        Log(LOG_LEVEL_ERR, "Some error occurred while communicating with "
                "wrapper.");
        free(options_str);
        return false;
    }
    
    if (!response)
    {
        Log(LOG_LEVEL_ERR, "error reading 'list-installed'");
        free(options_str);
        return false;
    }
    
    if (UpdatePackagesDB(response, wrapper->name, type) != 0)
    {
        Log(LOG_LEVEL_ERR, "error parsing and caching 'list-installed'");
        free(options_str);
        return false;
    }
    
    RlistDestroy(response);
    free(options_str);
    return true;
}


PromiseResult ValidateChangedPackage(const NewPackages *policy_data,
        const PackageManagerWrapper *wrapper, const PackageInfo *package_info,
        NewPackageAction action_type)
{
    
    if (!UpdateCache(policy_data->package_options, wrapper,
                     UPDATE_TYPE_INSTALLED))
    {
        Log(LOG_LEVEL_ERR, "Can not update cache after package installation");
        return PROMISE_RESULT_FAIL;
    }

    if (IsPackageInCache(wrapper->name, package_info->name,
                         package_info->arch, package_info->version))
    {
        return action_type == NEW_PACKAGE_ACTION_PRESENT ? 
            PROMISE_RESULT_CHANGE : PROMISE_RESULT_FAIL;
    }
    else
    {
        return action_type == NEW_PACKAGE_ACTION_PRESENT ? 
            PROMISE_RESULT_FAIL : PROMISE_RESULT_CHANGE;
    }
}

PromiseResult RemovePackage(const char *name, Rlist* options, 
        const char *version, const char *architecture,
        const PackageManagerWrapper *wrapper)
{
    Log(LOG_LEVEL_ERR, "Removing package '%s'", name);
             
    char *options_str = ParseOptions(options);
    char *ver = version ? 
        StringFormat("Version=%s\n", version) : NULL;
    char *arch = architecture ? 
        StringFormat("Architecture=%s\n", architecture) : NULL;
    char *request = StringFormat("%sName=%s%s%s\n",
            options_str, name, ver ? ver : "", arch ? arch : "");
    
    PromiseResult res = PROMISE_RESULT_CHANGE;
    
    Rlist *error_message = NULL;
    if (ReadWriteDataToPackageScript("remove", request, 
            &error_message, wrapper) != 0)
    {
        Log(LOG_LEVEL_ERR, "Some error occurred while communicating with "
                "wrapper.");
        res = PROMISE_RESULT_FAIL;
    }
    if (error_message)
    {
        ParseAndLogErrorMessage(error_message);
        res = PROMISE_RESULT_FAIL;
        RlistDestroy(error_message);
    }
    
    free(request);
    free(options_str);
    free(ver);
    free(arch);
    
    /* We assume that at this point package is removed correctly. */
    return res;    
}

PromiseResult HandleAbsentPromiseAction(char *package_name,
        const NewPackages *policy_data, const PackageManagerWrapper *wrapper)
{
    /* Check if we are not having 'latest' version. */
    if (policy_data->package_version &&
            StringSafeEqual(policy_data->package_version, "latest"))
    {
        Log(LOG_LEVEL_ERR, "Package version 'latest' not supported for"
                "absent package promise");
        return PROMISE_RESULT_FAIL;
    }
    
    /* Check if package exists in cache */
    if ((IsPackageInCache(wrapper->name, package_name,
         policy_data->package_architecture, policy_data->package_version)) == 1)
    {
        /* Remove package(s) */
        PromiseResult res = RemovePackage(package_name,
                policy_data->package_options, policy_data->package_version,
                policy_data->package_architecture, wrapper);
        
        if (res == PROMISE_RESULT_CHANGE)
        {
            return ValidateChangedPackage(policy_data, wrapper, 
                    &((PackageInfo){.name = package_name, 
                                    .version = policy_data->package_version, 
                                    .arch = policy_data->package_architecture}),
                    NEW_PACKAGE_ACTION_PRESENT);
        }
        
        return res;
    }
    
    /* Package in not there. */
    Log(LOG_LEVEL_ERR, "Package '%s' not installed. Skipping removing.",
            package_name);
    return PROMISE_RESULT_NOOP;
}

PromiseResult InstallPackage(Rlist *options, 
        PackageType type, const char *package_to_install,
        const char *version, const char *architecture,
        const PackageManagerWrapper *wrapper)
{
    Log(LOG_LEVEL_ERR, "Installing package '%s'", package_to_install);
             
    char *options_str = ParseOptions(options);
    char *ver = version ? 
        StringFormat("Version=%s\n", version) : NULL;
    char *arch = architecture ? 
        StringFormat("Architecture=%s\n", architecture) : NULL;
    char *request = NULL;
    
    PromiseResult res = PROMISE_RESULT_CHANGE;
    
    const char *package_install_command = NULL;
    if (type == PACKAGE_TYPE_FILE)
    {
        package_install_command = "file-install";
        request = StringFormat("%sFile=%s%s%s\n",
            options_str, package_to_install, ver ? ver : "", arch ? arch : "");
    }
    else if (type == PACKAGE_TYPE_REPO)
    {
        package_install_command = "repo-install";
        request = StringFormat("%sName=%s%s%s\n",
            options_str, package_to_install, ver ? ver : "", arch ? arch : "");
    }
    else
    {
        /* If we end up here something bad has happened. */
        assert(0 && "unsupported package type");
    }
    
    Rlist *error_message = NULL;
    if (ReadWriteDataToPackageScript(package_install_command, request, 
            &error_message, wrapper) != 0)
    {
        Log(LOG_LEVEL_ERR, "Some error occurred while communicating with "
                "wrapper.");
        res = PROMISE_RESULT_FAIL;
    }
    if (error_message)
    {
        ParseAndLogErrorMessage(error_message);
        res = PROMISE_RESULT_FAIL;
        RlistDestroy(error_message);
    }
    
    free(request);
    free(options_str);
    free(ver);
    free(arch);
    
    return res;
}

PromiseResult FileInstallPackage(const char *package_file_path, 
        const PackageInfo *info, const NewPackages *new_packages,
        const PackageManagerWrapper *wrapper,
        bool is_in_cache)
{
    Log(LOG_LEVEL_ERR, "FILE INSTALL PACKAGE");
    
    /* We have some packages matching file package promise in cache. */
    if (is_in_cache)
    {
        Log(LOG_LEVEL_ERR, "Package exists in cache. Exiting");
        return PROMISE_RESULT_NOOP;
    }
    
    PromiseResult res = InstallPackage(new_packages->package_options,
            PACKAGE_TYPE_FILE, package_file_path, NULL, NULL, wrapper);
    if (res == PROMISE_RESULT_CHANGE)
    {
        return ValidateChangedPackage(new_packages, wrapper, info,
                                      NEW_PACKAGE_ACTION_PRESENT);
    }
    return res;
}


Seq *GetVersionsFromUpdates(const PackageInfo *info, const char *pm_name)
{
    assert(pm_name);
    
    CF_DB *db_updates;
    dbid db_id = dbid_packages_updates;
    Seq *updates_list = SeqNew(100, FreePackageInfo);
    
    if (OpenSubDB(&db_updates, db_id, pm_name))
    {
        char package_key[strlen(info->name) + 3];

        xsnprintf(package_key, sizeof(package_key),
                "N<%s>", info->name);
        if (HasKeyDB(db_updates, package_key, strlen(package_key)))
        {
            size_t val_size =
                    ValueSizeDB(db_updates, package_key, strlen(package_key));
            char buff[val_size + 1];
            buff[val_size] = '\0';

            ReadDB(db_updates, package_key, buff, val_size);
            Seq* updates = SeqStringFromString(buff, '\n');
            
            for (int i = 0; i < SeqLength(updates); i++)
            {
                PackageInfo *package = calloc(1, sizeof(PackageInfo));

                char *package_line = SeqAt(updates, i);
                
                if (sscanf(package_line, "A<%s>V<%s>", package->arch,
                        package->version) == 2)
                {
                    SeqAppend(updates_list, package);
                }
                else
                {
                    /* Some error occurred while scanning package updates. */
                    FreePackageInfo(package);
                }
            }
        }
    }
    return updates_list;
}

PromiseResult RepoInstall(const PackageInfo *package_info,
        const NewPackages *policy_data, const PackageManagerWrapper *wrapper,
        bool is_in_cache)
{
    Log(LOG_LEVEL_ERR, "REPO INSTALL PACKAGE: %d", is_in_cache);
    
    if (!is_in_cache)
    {
        const char *version = package_info->version;
        if (package_info->version &&
                StringSafeEqual(package_info->version, "latest"))
        {
            version = NULL;
        }
        return InstallPackage(policy_data->package_options, PACKAGE_TYPE_REPO,
                package_info->name, version, package_info->arch, wrapper);
    }
    
    
    /* We have some packages matching already installed at this point. */
    
    
    /* We have 'latest' version in policy. */
    if (package_info->version &&
                StringSafeEqual(package_info->version, "latest"))
    {
        /* This can return more than one latest version if we have packages
         * for different architectures installed. */
        Seq *latest_versions = 
                GetVersionsFromUpdates(package_info, wrapper->name);
        if (!latest_versions)
        {
            Log(LOG_LEVEL_ERR, "Can not find exact package version(s) for "
                    "package '%s' with version latest", package_info->name);

            return PROMISE_RESULT_FAIL;
        }
        
        PromiseResult res = PROMISE_RESULT_NOOP;

        /* Loop through all currently installed packages and possible  updates. */
        for (int i = 0; i < SeqLength(latest_versions); i++)
        {
            PackageInfo *update_package = SeqAt(latest_versions, i);
            if (IsPackageInCache(wrapper->name, package_info->name,
                    update_package->arch, update_package->version))
            {
                res = PromiseResultUpdate(res, PROMISE_RESULT_NOOP);
                continue;
            }
            else
            {
                /* We are not sending 'update_package->version' to 
                 * wrapper as without version specified it should 
                 * install latest */
                PromiseResult upgrade_res =
                        InstallPackage(policy_data->package_options,
                        PACKAGE_TYPE_REPO, package_info->name,
                        NULL, package_info->arch, wrapper);
                res = PromiseResultUpdate(res, upgrade_res);
            }
        }
        SeqDestroy(latest_versions);
        return res;
    }
    /* No version or explicit version specified. */
    else
    {
        Log(LOG_LEVEL_ERR, "Package '%s' already installed",
                    package_info->name);
            
        return PROMISE_RESULT_NOOP;
    }
    /* Just to keep compiler happy; we shouldn't reach this point. */
    return PROMISE_RESULT_FAIL;
}

PromiseResult RepoInstallPackage(const PackageInfo *package_info,
        const NewPackages *policy_data, const PackageManagerWrapper *wrapper,
        bool is_in_cache)
{
    PromiseResult res = RepoInstall(package_info, policy_data, wrapper,
                                    is_in_cache);
    if (res == PROMISE_RESULT_CHANGE)
    {
        return ValidateChangedPackage(policy_data, wrapper, package_info,
                                      NEW_PACKAGE_ACTION_PRESENT);
    }
    return res;
}

static
bool CheckPolicyAndPackageInfoMatch(const NewPackages *packages_policy,
        const PackageInfo *info)
{
    /* Check if file we are having matches what we want in policy. */
    if (info->arch && packages_policy->package_architecture && 
            !StringSafeEqual(info->arch, packages_policy->package_architecture))
    {
        Log(LOG_LEVEL_ERR, 
            "package arch and one specified in policy doesn't match: %s -> %s",
            info->arch, packages_policy->package_architecture);
        return false;
    }
    if (info->version)
    {
        if (StringSafeEqual(packages_policy->package_version, "latest"))
        {
            Log(LOG_LEVEL_ERR, "unsupported 'latest' version for package "
                    "promise of type file.");
            return false;
        }
        if (packages_policy->package_version && 
            !StringSafeEqual(info->arch, packages_policy->package_architecture))
        {
            Log(LOG_LEVEL_ERR,
                "package version and one specified in policy doesn't match: %s -> %s",
                info->version, packages_policy->package_version);
            return false;
        }
    }
    return true;
}

PromiseResult HandlePresentPromiseAction(const char *package_name,
                           const NewPackages *new_packages,
                           const PackageManagerWrapper *package_manager_wrapper)
{
    Log(LOG_LEVEL_ERR, "PRESENT PROMISE ACTION");
    
    PackageError error = {0};
    /* Figure out what kind of package we are having. */
    PackageInfo *package_info = GetPackageData(package_name,
                                               new_packages->package_options,
                                               package_manager_wrapper, &error);
    
    PromiseResult result = PROMISE_RESULT_FAIL;
    if (package_info)
    {
        /* Check if data in policy matches returned by wrapper (files only). */
        if (package_info->type == PACKAGE_TYPE_FILE)
        {
            if (!CheckPolicyAndPackageInfoMatch(new_packages, package_info))
            {
                Log(LOG_LEVEL_ERR, "package data and policy doesn't match");
                FreePackageInfo(package_info);
                return PROMISE_RESULT_FAIL;
            }
        }
        
        /* Fill missing data in package_info from policy. This will allow
         * to match cache against all known package details we are interested */
        if (!package_info->arch && new_packages->package_architecture)
        {
            package_info->arch =
                    SafeStringDuplicate(new_packages->package_architecture);
        }
        if (!package_info->version && new_packages->package_version)
        {
            package_info->version =
                    SafeStringDuplicate(new_packages->package_version);
        }
        
        /* Check if package exists in cache */
        int is_in_cache = IsPackageInCache(package_manager_wrapper->name,
            package_info->name,
            package_info->arch, package_info->version);
        
        switch (package_info->type)
        {
            case PACKAGE_TYPE_FILE:
                result = FileInstallPackage(package_name, package_info,
                                            new_packages,
                                            package_manager_wrapper,
                                            is_in_cache);
                break;
            case PACKAGE_TYPE_REPO:
                result = RepoInstallPackage(package_info, new_packages,
                                            package_manager_wrapper,
                                            is_in_cache);
                break;
            default:
                /* We shouldn't end up here. If we are having unsupported 
                 package type this should be detected and handled
                 in ParseAndCheckPackageDataReply(). */
                assert(0 && "unsupported package type");
        }
        
        FreePackageInfo(package_info);
    }
    /* Some error occurred; let's check if we are having some error message. */
    LogPackagePromiseError(&error);
    
Log(LOG_LEVEL_ERR, "PRESENT PROMISE ACTION RETURNED: %c", result);
    return result;
}

//TODO: ifelapsed values can be NO_INT when parsing is failing!!!
PromiseResult HandleNewPackagePromiseType(EvalContext *ctx, const Promise *pp,
                                          Attributes *a)
{
    Log(LOG_LEVEL_ERR, "New package promise handler");
    
    if (!a->new_packages.package_manager ||
        !a->new_packages.package_manager->name)
    {
        Log(LOG_LEVEL_ERR, "Can not find package manager body.");
        return PROMISE_RESULT_FAIL;
    }
    
    PromiseBanner(ctx, pp);
    
    PackageManagerWrapper *package_manager_wrapper =
            GetPackageManagerWrapper(a->new_packages.package_manager->name);
    
    if (!package_manager_wrapper)
    {
        Log(LOG_LEVEL_ERR, 
            "Some error occurred while evaluating package promise: %s",
            pp->promiser);
        return PROMISE_RESULT_FAIL;
    }
    
    const char *lockname = "new_packages_promise_lock";
    CfLock package_promise_global_lock;
    CfLock package_promise_lock;
    
    char promise_lock[CF_BUFSIZE];
    snprintf(promise_lock, CF_BUFSIZE - 1, "new-package-%s-%s",
             pp->promiser, a->new_packages.package_manager->name);

    package_promise_global_lock =
            AcquireLock(ctx, lockname, VUQNAME, CFSTARTTIME,
                        (TransactionContext) {.ifelapsed = 0, .expireafter = 0},
                        pp, false);
    if (package_promise_global_lock.lock == NULL)
    {
        Log(LOG_LEVEL_ERR, 
            "Can not aquire global lock for package promise. Skipping promise "
            "evaluation");
        return PROMISE_RESULT_SKIPPED;
    }
    
    package_promise_lock =
            AcquireLock(ctx, promise_lock, VUQNAME, CFSTARTTIME,
            a->transaction, pp, false);
    if (package_promise_lock.lock == NULL)
    {
        Log(LOG_LEVEL_ERR, 
            "Can not aquire lock for '%s' package promise. Skipping promise "
            "evaluation",  pp->promiser);
        YieldCurrentLockAndRemoveFromCache(ctx, package_promise_global_lock,
                                           lockname, pp);
        return PROMISE_RESULT_SKIPPED;
    }
    
    PromiseResult result = PROMISE_RESULT_FAIL;
    
    switch (a->new_packages.package_policy)
    {
        case NEW_PACKAGE_ACTION_ABSENT:
            result = HandleAbsentPromiseAction(pp->promiser, 
                                               &a->new_packages,
                                               package_manager_wrapper);
            break;
        case NEW_PACKAGE_ACTION_PRESENT:
            result = HandlePresentPromiseAction(pp->promiser, 
                                                &a->new_packages,
                                                package_manager_wrapper);
            break;
        case NEW_PACKAGE_ACTION_NONE:
        default:
            Log(LOG_LEVEL_ERR, "Unsupported or missing package promise policy.");
            result = PROMISE_RESULT_FAIL;
            break;
    }
    
    FreePackageManageWrapper(package_manager_wrapper);
    
    YieldCurrentLock(package_promise_lock);
    YieldCurrentLockAndRemoveFromCache(ctx, package_promise_global_lock,
                                       lockname, pp);
    
    return result;
}
