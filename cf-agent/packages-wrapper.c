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

#define INVENTORY_LIST_BUFFER_SIZE 100 * 80 /* 100 entries with 80 characters 
                                             * per line */

static
bool UpdateSinglePackageModuleCache(EvalContext *ctx,
                                    const PackageManagerWrapper *module_wrapper,
                                    UpdateType type, bool force_update);

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
            Log(LOG_LEVEL_DEBUG, "Data red from package module: %zu [%s]",
                res, buff);
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

static
int WriteScriptData(const char *data, IOData *io)
{
    if (data == NULL || strlen(data) == 0)
    {
        if (io->write_fd >= 0)
        {
            close(io->write_fd);
            io->write_fd = -1;
        }
        return 0;
    }
    
    ssize_t wrt = write(io->write_fd, data, strlen(data));
    
    /* Make sure to close write_fd after sending all data. */
    if (io->write_fd >= 0)
    {
        close(io->write_fd);
        io->write_fd = -1;
    }
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
    assert(args && wrapper);
    
    char *command = StringFormat("%s %s", wrapper->path, args);
    IOData io = cf_popen_full_duplex(command, false);
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
    
    return StringFormat("%s%c%s%c%s", GetWorkDir(), FILE_SEPARATOR, "package_modules",
            FILE_SEPARATOR, package_manager_name);
}

static
void FreePackageManageWrapper(PackageManagerWrapper *wrapper)
{
    free(wrapper->path);
    free(wrapper->name);
    free(wrapper);
}

static
PackageManagerWrapper *GetPackageManagerWrapper(PackageManagerBody *package_module)
{
    assert(package_module && package_module->name);
    //TODO: add cache where managers are already initialized from previous runs
    PackageManagerWrapper *wrapper = malloc(sizeof(PackageManagerWrapper));
    
    if (!wrapper)
    {
        return NULL;
    }
    
    wrapper->path = GetPackageWrapperRealPath(package_module->name);
    wrapper->name = SafeStringDuplicate(package_module->name);
    wrapper->package_module = package_module;
    
    /* Check if file exists */
    struct stat sb;
    if (!wrapper->path || (stat(wrapper->path, &sb) != 0))
    {
        Log(LOG_LEVEL_ERR,
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
int IsPackageInCache(EvalContext *ctx,
                     const PackageManagerWrapper *module_wrapper,
                     const char *name, const char *ver, const char *arch)
{
    const char *version = ver;
    /* Handle latest version in specific way for repo packages. 
     * Please note that for file packages 'latest' version is not supported
     * and check against that is made elsewhere. */
    if (version && StringSafeEqual(version, "latest"))
    {
        version = NULL;
    }
    
    /* Make sure cache is updated. */
    if (ctx)
    {
        if (!UpdateSinglePackageModuleCache(ctx, module_wrapper,
                                            UPDATE_TYPE_INSTALLED, false))
        {
            Log(LOG_LEVEL_ERR, "Can not update cache");
        }
    }
    
    CF_DB *db_cached;
    if (!OpenSubDB(&db_cached, dbid_packages_installed,
                   module_wrapper->package_module->name))
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
    else
    {
         key = StringFormat("N<%s>", name);
    }
    
    int is_in_cache = 0;
    char buff[1];
    
    Log(LOG_LEVEL_ERR, "looking for package in cache: %s", key);
    
    if (ReadDB(db_cached, key, buff, 1))
    {
        /* Just make sure DB is not corrupted. */
        if (buff[0] == '1')
        {
            is_in_cache = 1;
        }
        else
        {
            is_in_cache = -1;
        }
    }
    
    Log(LOG_LEVEL_ERR, "package %s in cache", 
        is_in_cache == 0 ? "not found" : "found");
    
    CloseDB(db_cached);
    
    return is_in_cache;
}

void WritePackageDataToDB(CF_DB *db_installed,
        const char *name, const char *ver, const char *arch,
        UpdateType type)
{
    char package_key[strlen(name) + strlen(ver) +
                     strlen(arch) + 11];
    
    xsnprintf(package_key, sizeof(package_key),
              "N<%s>", name);
    if ((type == UPDATE_TYPE_UPDATES || type == UPDATE_TYPE_LOCAL_UPDATES) && 
            HasKeyDB(db_installed, package_key, strlen(package_key) + 1))
    {
        size_t val_size =
                ValueSizeDB(db_installed, package_key, strlen(package_key));
        char buff[val_size + strlen(arch) + strlen(ver) + 8];
        
        ReadDB(db_installed, package_key, buff, val_size);
        xsnprintf(buff + val_size, sizeof(package_key), "V<%s>A<%s>\n", ver, arch);
        WriteDB(db_installed, package_key, buff, strlen(buff));
    }
    else if (type == UPDATE_TYPE_UPDATES || type == UPDATE_TYPE_LOCAL_UPDATES)
    {
        char buff[strlen(arch) + strlen(ver) + 8];
        xsnprintf(buff, sizeof(package_key), "V<%s>A<%s>\n", ver, arch);
        WriteDB(db_installed, package_key, buff, strlen(buff));
    }
    else /* UPDATE_TYPE_INSTALLED */
    {
        WriteDB(db_installed, package_key, "1", 1);
        xsnprintf(package_key, sizeof(package_key),
                "N<%s>V<%s>", name, ver);
        WriteDB(db_installed, package_key, "1", 1);
        xsnprintf(package_key, sizeof(package_key),
                "N<%s>A<%s>", name, arch);
        WriteDB(db_installed, package_key, "1", 1);
        xsnprintf(package_key, sizeof(package_key),
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
        
        Buffer *inventory_data = BufferNewWithCapacity(INVENTORY_LIST_BUFFER_SIZE);

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
                    
                    char inventory_line[strlen(package_data[0]) +
                                        strlen(package_data[1]) +
                                        strlen(package_data[2]) + 4];
                    
                    xsnprintf(inventory_line, sizeof(inventory_line),
                              "%s,%s,%s\n", package_data[0], package_data[1],
                              package_data[2]);
                    BufferAppendString(inventory_data, inventory_line);

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
            
            char inventory_line[strlen(package_data[0]) +
                                strlen(package_data[1]) +
                                strlen(package_data[2]) + 4];

            xsnprintf(inventory_line, sizeof(inventory_line),
                      "%s,%s,%s\n", package_data[0], package_data[1],
                      package_data[2]);
            BufferAppendString(inventory_data, inventory_line);
        }
        
        char *inventory_key = "<inventory>";
        char *inventory_list = BufferClose(inventory_data);
        WriteDB(db_cached, inventory_key, inventory_list, strlen(inventory_list));
        free(inventory_list);
        
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
    
    const char *req_type = NULL;
    if (type == UPDATE_TYPE_INSTALLED)
    {
        req_type = "list-installed";
    }
    else if (type == UPDATE_TYPE_UPDATES)
    {
        req_type = "list-updates";
    }
    else if (type == UPDATE_TYPE_LOCAL_UPDATES)
    {
        //TODO:
        //req_type = "list-updates-locally";
        req_type = "list-updates";
    }
    if (ReadWriteDataToPackageScript(req_type, options_str, &response,
            wrapper) != 0)
    {
        Log(LOG_LEVEL_ERR, "Some error occurred while communicating with "
                "wrapper.");
        free(options_str);
        return false;
    }
    
    if (!response)
    {
        Log(LOG_LEVEL_ERR, "error reading %s", req_type);
        free(options_str);
        return false;
    }
    
    if (UpdatePackagesDB(response, wrapper->name, type) != 0)
    {
        Log(LOG_LEVEL_ERR, "error parsing cache data");
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
    
    if (!UpdateCache(policy_data->package_options, wrapper,
                     UPDATE_TYPE_LOCAL_UPDATES))
    {
        Log(LOG_LEVEL_ERR, "Can not update available updates cache after "
            "package installation");
        return PROMISE_RESULT_FAIL;
    }

    if (IsPackageInCache(NULL, wrapper, package_info->name,
                         package_info->version, package_info->arch))
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
    char *request = StringFormat("%sName=%s\n%s%s",
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

PromiseResult HandleAbsentPromiseAction(EvalContext *ctx,
                                        char *package_name,
                                        const NewPackages *policy_data, 
                                        const PackageManagerWrapper *wrapper)
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
    if ((IsPackageInCache(ctx, wrapper, package_name,
                          policy_data->package_version,
                          policy_data->package_architecture)) == 1)
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
        request = StringFormat("%sFile=%s\n%s%s",
            options_str, package_to_install, ver ? ver : "", arch ? arch : "");
    }
    else if (type == PACKAGE_TYPE_REPO)
    {
        package_install_command = "repo-install";
        request = StringFormat("%sName=%s\n%s%s",
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
        int is_in_cache)
{
    Log(LOG_LEVEL_ERR, "FILE INSTALL PACKAGE");
    
    /* We have some packages matching file package promise in cache. */
    if (is_in_cache == 1)
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


Seq *GetVersionsFromUpdates(EvalContext *ctx, const PackageInfo *info,
                            const PackageManagerWrapper *module_wrapper)
{   
    CF_DB *db_updates;
    dbid db_id = dbid_packages_updates;
    Seq *updates_list = NULL;
    
    /* Make sure cache is updated. */
    if (ctx)
    {
        if (!UpdateSinglePackageModuleCache(ctx, module_wrapper,
                                            UPDATE_TYPE_UPDATES, false))
        {
            Log(LOG_LEVEL_ERR, "Can not update cache");
        }
    }
    
    if (OpenSubDB(&db_updates, db_id, module_wrapper->package_module->name))
    {
        char package_key[strlen(info->name) + 4];

        xsnprintf(package_key, sizeof(package_key),
                "N<%s>", info->name);
        
        Log(LOG_LEVEL_ERR, "looking for key in updates: %s %zu",
            package_key, strlen(package_key));
         
        if (HasKeyDB(db_updates, package_key, sizeof(package_key)))
        {
            Log(LOG_LEVEL_ERR, "found key in updates database");
            
            updates_list = SeqNew(3, FreePackageInfo);
            size_t val_size =
                    ValueSizeDB(db_updates, package_key, sizeof(package_key));
            char buff[val_size + 1];
            buff[val_size] = '\0';

            ReadDB(db_updates, package_key, buff, val_size);
            Seq* updates = SeqStringFromString(buff, '\n');
            
            for (int i = 0; i < SeqLength(updates); i++)
            {
                PackageInfo *package = calloc(1, sizeof(PackageInfo));

                char *package_line = SeqAt(updates, i);
                
                Log(LOG_LEVEL_DEBUG, "inside updates: %s", package_line);
                
                char version[strlen(package_line)];
                char arch[strlen(package_line)];

                if (sscanf(package_line, "V<%[^>]>A<%[^>]>", version, arch) == 2)
                {
                    package->version = SafeStringDuplicate(version);
                    package->arch = SafeStringDuplicate(arch);
                    SeqAppend(updates_list, package);
                }
                else
                {
                    Log(LOG_LEVEL_ERR, "not able to parse available updates "
                        "line: %s", package_line);
                    /* Some error occurred while scanning package updates. */
                    FreePackageInfo(package);
                }
            }
        }
        CloseDB(db_updates);
    }
    return updates_list;
}

PromiseResult RepoInstall(EvalContext *ctx,
                          PackageInfo *package_info,
                          const NewPackages *policy_data,
                          const PackageManagerWrapper *wrapper,
                          int is_in_cache)
{
    Log(LOG_LEVEL_ERR, "REPO INSTALL PACKAGE: %d", is_in_cache);
    
    if (is_in_cache == 0)
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
                GetVersionsFromUpdates(ctx, package_info, wrapper);
        if (!latest_versions)
        {
            Log(LOG_LEVEL_ERR, "Package '%s' is already in the latest version.",
                package_info->name);

            return PROMISE_RESULT_NOOP;
        }
        
        PromiseResult res = PROMISE_RESULT_NOOP;

        /* Loop through all currently installed packages and possible  updates. */
        for (int i = 0; i < SeqLength(latest_versions); i++)
        {
            PackageInfo *update_package = SeqAt(latest_versions, i);
            
            Log(LOG_LEVEL_ERR, "Checking for package '%s' version '%s' in "
                    "available updates", package_info->name,
                    update_package->version);
            
            /* Just in case some package managers will report highest possible 
               version in updates list */
            if (IsPackageInCache(ctx, wrapper, package_info->name,
                                 update_package->version,
                                 update_package->arch))
            {
                Log(LOG_LEVEL_ERR, "Package version from updates matches "
                        "one installed. Skipping package instalation.");
                res = PromiseResultUpdate(res, PROMISE_RESULT_NOOP);
                continue;
            }
            else
            {
                package_info->version =
                        SafeStringDuplicate(update_package->version);
                
                PromiseResult upgrade_res =
                        InstallPackage(policy_data->package_options,
                        PACKAGE_TYPE_REPO, package_info->name,
                        package_info->version, package_info->arch, wrapper);
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

PromiseResult RepoInstallPackage(EvalContext *ctx, 
                                 PackageInfo *package_info,
                                 const NewPackages *policy_data,
                                 const PackageManagerWrapper *wrapper,
                                 int is_in_cache)
{
    PromiseResult res = RepoInstall(ctx, package_info, policy_data, wrapper,
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

PromiseResult HandlePresentPromiseAction(EvalContext *ctx, 
                                         const char *package_name,
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
        int is_in_cache = IsPackageInCache(ctx, package_manager_wrapper,
                                           package_info->name,
                                           package_info->version,
                                           package_info->arch);
        
        if (is_in_cache == -1)
        {
            Log(LOG_LEVEL_ERR, "Some error occurred while looking for package "
                    "'%s' in cache.", package_name);
            return PROMISE_RESULT_FAIL;
        }
        
        switch (package_info->type)
        {
            case PACKAGE_TYPE_FILE:
                result = FileInstallPackage(package_name, package_info,
                                            new_packages,
                                            package_manager_wrapper,
                                            is_in_cache);
                break;
            case PACKAGE_TYPE_REPO:
                result = RepoInstallPackage(ctx, package_info, new_packages,
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
                                          Attributes *a, char **promise_log_msg,
                                          LogLevel *log_lvl)
{
    Log(LOG_LEVEL_ERR, "New package promise handler");
    
    if (!a->new_packages.package_manager ||
        !a->new_packages.package_manager->name)
    {
        Log(LOG_LEVEL_ERR, "Can not find package manager body.");
        *promise_log_msg =
                SafeStringDuplicate("Can not find package manager body.");
        *log_lvl = LOG_LEVEL_ERR;
        return PROMISE_RESULT_FAIL;
    }
    
    PromiseBanner(ctx, pp);
    
    const char *lockname = GLOBAL_PACKAGE_PROMISE_LOCK_NAME;
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
        
        *promise_log_msg =
                SafeStringDuplicate("Can not aquire global lock for package "
                                    "promise. Skipping promise evaluation");
        *log_lvl = LOG_LEVEL_VERBOSE;
        
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
        
        *promise_log_msg =
                StringFormat("Can not aquire lock for '%s' package promise. "
                             "Skipping promise evaluation",  pp->promiser);
        *log_lvl = LOG_LEVEL_VERBOSE;
        
        return PROMISE_RESULT_SKIPPED;
    }
    
    PackageManagerWrapper *package_manager_wrapper =
            GetPackageManagerWrapper(a->new_packages.package_manager);
    
    if (!package_manager_wrapper)
    {
        Log(LOG_LEVEL_ERR, 
            "Some error occurred while contacting package module for promise: %s",
            pp->promiser);
        *promise_log_msg =
                StringFormat("Some error occurred while contacting package "
                             "module for promise: %s", pp->promiser);
        *log_lvl = LOG_LEVEL_ERR;
        return PROMISE_RESULT_FAIL;
    }
    
    PromiseResult result = PROMISE_RESULT_FAIL;
    
    switch (a->new_packages.package_policy)
    {
        case NEW_PACKAGE_ACTION_ABSENT:
            result = HandleAbsentPromiseAction(ctx, pp->promiser, 
                                               &a->new_packages,
                                               package_manager_wrapper);
            *log_lvl = result == PROMISE_RESULT_FAIL ?
                                 LOG_LEVEL_ERR : LOG_LEVEL_VERBOSE;
            *promise_log_msg = result == PROMISE_RESULT_FAIL ?
                StringFormat("Error removing package '%s'", pp->promiser) :
                StringFormat("Successfully removed package '%s'", pp->promiser);
            break;
        case NEW_PACKAGE_ACTION_PRESENT:
            result = HandlePresentPromiseAction(ctx, pp->promiser, 
                                                &a->new_packages,
                                                package_manager_wrapper);
            *log_lvl = result == PROMISE_RESULT_FAIL ?
                                 LOG_LEVEL_ERR : LOG_LEVEL_VERBOSE;
            *promise_log_msg = result == PROMISE_RESULT_FAIL ?
                StringFormat("Error installing package '%s'", pp->promiser) :
                StringFormat("Successfully installed package '%s'", pp->promiser);
            break;
        case NEW_PACKAGE_ACTION_NONE:
        default:
            Log(LOG_LEVEL_ERR, "Unsupported or missing package promise policy.");
            result = PROMISE_RESULT_FAIL;
            
            *promise_log_msg =
                SafeStringDuplicate("Unsupported or missing package promise "
                                    "policy.");
            *log_lvl = LOG_LEVEL_ERR;

            break;
    }
    
    FreePackageManageWrapper(package_manager_wrapper);
    
    YieldCurrentLock(package_promise_lock);
    YieldCurrentLockAndRemoveFromCache(ctx, package_promise_global_lock,
                                       lockname, pp);
    
    return result;
}

/* This must be called under protection of GLOBAL_PACKAGE_PROMISE_LOCK_NAME lock! */
bool UpdateSinglePackageModuleCache(EvalContext *ctx,
                                    const PackageManagerWrapper *module_wrapper,
                                    UpdateType type, bool force_update)
{
    assert(module_wrapper->package_module->name);
    
    if (!force_update)
    {
        if (module_wrapper->package_module->installed_ifelapesed == CF_NOINT ||
            module_wrapper->package_module->updates_ifelapsed == CF_NOINT)
        {
            Log(LOG_LEVEL_ERR, "Package module body constraints error: %s %d %d",
                module_wrapper->package_module->name, 
                module_wrapper->package_module->installed_ifelapesed,
                module_wrapper->package_module->updates_ifelapsed);
            return false;
        }
    }
    
    Bundle bundle = {.name = "package_cache"};
    PromiseType promie_type = {.name = "package_cache",
                               .parent_bundle = &bundle};
    Promise pp = {.promiser = "package_cache",
                  .parent_promise_type = &promie_type};

    CfLock cache_updates_lock;
    char cache_updates_lock_name[CF_BUFSIZE];

    if (type == UPDATE_TYPE_INSTALLED)
    {
        snprintf(cache_updates_lock_name, CF_BUFSIZE - 1,
                 "package-cache-installed-%s", module_wrapper->package_module->name);
    }
    else
    {
        snprintf(cache_updates_lock_name, CF_BUFSIZE - 1,
                "package-cache-updates-%s", module_wrapper->package_module->name);
    }

    if (!force_update)
    {
        cache_updates_lock =
                AcquireLock(ctx, cache_updates_lock_name, VUQNAME, CFSTARTTIME,
                (TransactionContext) {.ifelapsed = module_wrapper->package_module->updates_ifelapsed, .expireafter = 0},
                &pp, false);
    }
    
    bool ret = true;

    if (force_update || cache_updates_lock.lock != NULL)
    {
        
        /* Update available updates cache. */
        if (!UpdateCache(module_wrapper->package_module->options, module_wrapper, type))
        {
            Log(LOG_LEVEL_ERR, "Some error occurred while updating available "
                               "updates cache.");
            ret = false;
        }
        if (!force_update)
        {
            YieldCurrentLock(cache_updates_lock);
        }
    }
    else
    {
        Log(LOG_LEVEL_ERR, "Skipping available updates package cache update "
                           "due to ifelapesed.");
    }
    return ret;
}

void UpdatePackagesCache(EvalContext *ctx, bool force_update)
{
    Log(LOG_LEVEL_ERR, "Updating package cache.");
    const char *lockname = GLOBAL_PACKAGE_PROMISE_LOCK_NAME;
    CfLock package_promise_global_lock;
    
    Bundle bundle = {.name = "package_cache"};
    PromiseType promie_type = {.name = "package_cache",
                               .parent_bundle = &bundle};
    Promise pp = {.promiser = "package_cache",
                  .parent_promise_type = &promie_type};

    package_promise_global_lock =
            AcquireLock(ctx, lockname, VUQNAME, CFSTARTTIME,
                        (TransactionContext) {.ifelapsed = 0, .expireafter = 0},
                        &pp, false);
                        
    if (package_promise_global_lock.lock == NULL)
    {
        Log(LOG_LEVEL_ERR, "Can not aquire global lock for package promise. "
            "Skipping updating cache.");
        return;
    }
                        
    Rlist *default_inventory = GetDefaultInventoryFromPackagePromiseContext(ctx);
    
    for (const Rlist *rp = default_inventory; rp != NULL; rp = rp->next)
    {
        const char *pm_name =  RlistScalarValue(rp);
        
        /* We don't want inventory to be reported. */
        if (StringSafeEqual(pm_name, "cf_null"))
        {
            break;
        }
        PackageManagerBody *module =
                GetManagerFromPackagePromiseContext(ctx, pm_name);

        if (!module)
        {
            Log(LOG_LEVEL_ERR, "Can not find body for package module: %s",
                pm_name);
            continue;
        }

        PackageManagerWrapper *module_wrapper =
                GetPackageManagerWrapper(module);

        if (!module_wrapper)
        {
            Log(LOG_LEVEL_ERR, "Can not set up wrapper for module: %s", pm_name);
            continue;
        }

        UpdateSinglePackageModuleCache(ctx, module_wrapper,
                                       UPDATE_TYPE_INSTALLED, force_update);
        UpdateSinglePackageModuleCache(ctx, module_wrapper,
                                       force_update ? UPDATE_TYPE_LOCAL_UPDATES : 
                                           UPDATE_TYPE_UPDATES,
                                       force_update);

        FreePackageManageWrapper(module_wrapper);
        
    }
    YieldCurrentLockAndRemoveFromCache(ctx, package_promise_global_lock,
                                       lockname, &pp);
}
