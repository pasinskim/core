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

#define PACKAGE_PROMISE_SCRIPT_TIMEOUT_SEC 5

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
    
    while(!IsPendingTermination())
    {
        int fd = IsReadWriteReady(io, PACKAGE_PROMISE_SCRIPT_TIMEOUT_SEC);
        
        if (fd <= 0)
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
    IOData io = cf_popen_full_duplex(command, true);
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
void FreePackageInfo(PackageInfo *package_info)
{
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
    PackageInfo *package_data = xcalloc(1, sizeof(PackageInfo));
    
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
                FreePackageInfo(package_data);
                return NULL;
            }
        }
        else if (StringStartsWith(line, "Name="))
        {
            package_data->name = 
                SafeStringDuplicate(line + strlen("Name="));
        }
        else if (StringStartsWith(line, "Version="))
        {
            package_data->version = 
                SafeStringDuplicate(line + strlen("Version="));
        }
        else if (StringStartsWith(line, "Architecture="))
        {
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
    
    /* At this point at least package name MUST be known (if no error) */
    if (!package_data || !package_data->name)
    {
        Log(LOG_LEVEL_ERR, "can not figure out package name");
        FreePackageInfo(package_data);
        return NULL;
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
        return NULL;
    }
    PackageInfo *package_data = NULL;
    
    if (response)
    {
        package_data = ParseAndCheckPackageDataReply(response, error);
        RlistDestroy(response);
    }
    free(options_str);
    free(request);
        
    return package_data;
}

static
char *GetPackageWrapperRealPath(const char *package_manager_name)
{
    
    return StringFormat("%s%c%s%c%s", GetWorkDir(), FILE_SEPARATOR, "package_managers",
            FILE_SEPARATOR, package_manager_name);
}

static
void FreePackageManageWrapper(PackageManagerWrapper *wrapper)
{
    free(wrapper->path);
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

//TODO: ?
/* Returns list of all matching packages (may be more than one if arch or
 * version is not specified). */
static
PackageInfoList *IsPackageInCache(const char *name, const char *arch,
        const char *ver, PackageType type)
{
    const char *version = ver;
    /* Handle latest version in specific way for repo packages. 
     * Please note that for file packages 'latest' version is not supported
     * and check against that is made elsewhere. */
    if (version && StringSafeEqual(version, "latest"))
    {
        version = NULL;
    }
    
    //return GetFromCache(name, arch, version);
    
    
    return NULL;
}

static
void PackagesListDestroy(PackageInfoList *list)
{
    while (list)
    {
        PackageInfoList *next = list->next;
        FreePackageInfo(list->package);
        free(list);
        list = next;
    }
}

//TOOD:
bool GetListInstalled(Rlist* options, const PackageManagerWrapper *wrapper)
{
    char *options_str = ParseOptions(options);
    Rlist *response = NULL;
    if (ReadWriteDataToPackageScript("list-installed", options_str, &response,
            wrapper) != 0)
    {
        Log(LOG_LEVEL_ERR, "Some error occurred while communicating with "
                "wrapper.");
        return false;
    }
    
    if (!response)
    {
        Log(LOG_LEVEL_ERR, "error reading 'list-installed'");
        free(options_str);
        return false;
    }
    Log(LOG_LEVEL_ERR, "have installed packages");
    
    RlistDestroy(response);
    free(options_str);
    return true;
}

//TODO:
bool GetListUpdates(Rlist* options, const PackageManagerWrapper *wrapper)
{
    char *options_str = ParseOptions(options);
    Rlist *response = NULL;
    if (ReadWriteDataToPackageScript("list-updates", options_str, &response,
            wrapper) != 0)
    {
        Log(LOG_LEVEL_ERR, "Some error occurred while communicating with "
                "wrapper.");
        return false;
    }
    
    if (!response)
    {
        Log(LOG_LEVEL_ERR, "error reading 'list-updates'");
        free(options_str);
        return false;
    }
    
    Log(LOG_LEVEL_ERR, "have list of updates");
    
    RlistDestroy(response);
    free(options_str);
    return true;
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
    
    //TODO: figure out result
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

PromiseResult HandleAbsentPromiseAction(const char *package_name,
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
    
    PackageInfoList *packages_from_cache = NULL;
    /* Check if package exists in cache */
    if ((packages_from_cache = IsPackageInCache(package_name,
            policy_data->package_architecture,
            policy_data->package_version, PACKAGE_TYPE_REPO)))
    {
        /* Remove package(s) */
        PromiseResult res = RemovePackage(package_name,
                policy_data->package_options, policy_data->package_version,
                policy_data->package_architecture, wrapper);
        
        PackagesListDestroy(packages_from_cache);
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
    
    //TODO: figure out result
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
    
    /* We assume that at this point package is installed correctly. */
    return res;
}

PromiseResult FileInstallPackage(const char *package_file_path, 
        const NewPackages *new_packages,
        const PackageManagerWrapper *wrapper,
        PackageInfoList *cached_packages)
{
    Log(LOG_LEVEL_ERR, "FILE INSTALL PACKAGE");
    
    /* We have some packages matching file package promise in cache. */
    if (cached_packages)
    {
        Log(LOG_LEVEL_ERR, "Package exists in cache. Exiting");
        PackagesListDestroy(cached_packages);
        return PROMISE_RESULT_NOOP;
    }
    
    return InstallPackage(new_packages->package_options, PACKAGE_TYPE_FILE,
            package_file_path, NULL, NULL, wrapper);
}

//TODO: implement me
PackageInfoList *GetVersionsFromUpdates(const PackageInfo *package_info)
{
    //TODO: what if architecture will not be provided
    //if more than one entry here return error and stop
    if (StringSafeEqual(package_info->name, "lynx"))
        return NULL;
    return NULL;
}

PromiseResult RepoInstallPackage(const PackageInfo *package_info,
        const NewPackages *policy_data, const PackageManagerWrapper *wrapper,
        PackageInfoList *cached_packages)
{
    Log(LOG_LEVEL_ERR, "REPO INSTALL PACKAGE");
    
    if (!cached_packages)
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
        /* We can have one or more packages in 'cached_packages' here. */
        
        
        /* This can return more than one latest version if we have packages
         * for different architectures installed. */
        PackageInfoList *latest_versions = GetVersionsFromUpdates(package_info);
        if(!latest_versions)
        {
            Log(LOG_LEVEL_ERR, "Can not find exact package version(s) for "
                    "package '%s' with version latest", package_info->name);

            PackagesListDestroy(cached_packages);
            return PROMISE_RESULT_FAIL;
        }
        
        PromiseResult res = PROMISE_RESULT_NOOP;
        
        /* Loop through all currently installed packages and possible  updates. */
        for (PackageInfoList *ver = latest_versions; ver != NULL; ver = ver->next)
        {
            PackageInfo *update_package = ver->package;
            for (PackageInfoList *curr = cached_packages; curr != NULL; curr = curr->next)
            {
                PackageInfo *current_package = curr->package;
                if (!current_package->arch || !current_package->version ||
                    !update_package->arch || !update_package->version)
                {
                    Log(LOG_LEVEL_ERR, "Some needed data not returned by "
                            "'list-installed' or 'list-updated' command or"
                            "cache broken.");
                    PackagesListDestroy(cached_packages);
                    PackagesListDestroy(latest_versions);
                    return PROMISE_RESULT_FAIL;
                }
                if (StringSafeEqual(current_package->arch, update_package->arch))
                {
                    if (StringSafeEqual(current_package->version, 
                            update_package->version))
                    {
                         Log(LOG_LEVEL_ERR, "Package '%s' version '%s' and "
                                 "architecture '%s' already installed",
                                 current_package->name,
                                 current_package->arch, current_package->version);
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
            }
        }
        PackagesListDestroy(cached_packages);
        PackagesListDestroy(latest_versions);
        return res;
    }
    /* No version or explicit version specified. */
    else
    {
        Log(LOG_LEVEL_ERR, "Package '%s' already installed",
                    package_info->name);
            
        PackagesListDestroy(cached_packages);
        return PROMISE_RESULT_NOOP;
    }
    /* Just to keep compiler happy; we shouldn't reach this point. */
    return PROMISE_RESULT_FAIL;
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
        PackageInfoList *cached_packages = IsPackageInCache(package_info->name,
            package_info->arch, package_info->version,
            package_info->type);
        
        switch (package_info->type)
        {
            /* IMPORTANT: Both FileInstallPackage() and 
             * RepoInstallPackage() take ownership of cached_packages and
             * are responsible to call free. */
            case PACKAGE_TYPE_FILE:
                result = FileInstallPackage(package_name,
                                            new_packages,
                                            package_manager_wrapper,
                                            cached_packages);
                break;
            case PACKAGE_TYPE_REPO:
                result = RepoInstallPackage(package_info, new_packages,
                                            package_manager_wrapper,
                                            cached_packages);
                break;
            default:
                /* We shouldn't end up here. If we are having unsupported 
                 package type this should be detected and handled
                 in ParseAndCheckPackageDataReply(). */
                assert(0 && "unsupported package type");
        }
        if (result == PROMISE_RESULT_CHANGE)
        {
            //TODO: run 'list-installed' and see if package is there
            //TODO: update cache
        }
        
        FreePackageInfo(package_info);
    }
    /* Some error occurred; let's check if we are having some error message. */
    LogPackagePromiseError(&error);
    
Log(LOG_LEVEL_ERR, "PRESENT PROMISE ACTION RETURNED: %c", result);
    return result;
}

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
    
    //TODO: lock
    
    PackageManagerWrapper *package_manager_wrapper =
            GetPackageManagerWrapper(a->new_packages.package_manager->name);
    
    if (!package_manager_wrapper)
    {
        Log(LOG_LEVEL_ERR, 
            "Some error occurred while evaluating package promise: %s",
            pp->promiser);
        return PROMISE_RESULT_FAIL;
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
    //TODO: unlock
    
    FreePackageManageWrapper(package_manager_wrapper);
    
    return result;
}
