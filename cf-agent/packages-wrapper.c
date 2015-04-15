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

Rlist *ReadWriteDataToPackageScript(const char *args, const char *data,
                                    const PackageManagerWrapper *wrapper)
{
    char *command = StringFormat("%s %s", wrapper->path, args);
    IOData io = cf_popen_full_duplex(command, true);
    free(command);
    
    if (io.write_fd == 0 || io.read_fd == 0)
    {
        Log(LOG_LEVEL_VERBOSE, "some error occurred while communicating "
                "package manager script");
        return NULL;
    }
    
    if (WriteScriptData(data, &io) != strlen(data))
    {
        Log(LOG_LEVEL_ERR, "couldn't write whole data to script");
        return NULL;
    }
    
    Rlist *response = RedDataFromPackageScript(&io);
    
    /* If script returns non 0 status */
    if (cf_pclose_full_duplex(&io) != EXIT_SUCCESS)
    {
        Log(LOG_LEVEL_VERBOSE,
            "package manager script returned with failure");
        RlistDestroy(response);
        response = NULL;
    }
    
    return response;
}

static int NegotiateSupportedAPIVersion(PackageManagerWrapper *wrapper)
{
    int api_version = -1;

    Rlist *response = ReadWriteDataToPackageScript("supports-api-version", "", wrapper);
    
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

static
PackageInfo *GetPackageData(const char *name, Rlist *options,
                            const PackageManagerWrapper *wrapper, 
                            PackageError *error)
{
    char *options_str = ParseOptions(options);
    const char *request = StringFormat("%sFile=%s\n",
                                 options_str, name);
    
    Rlist *response = ReadWriteDataToPackageScript("get-package-data", request, wrapper);
    PackageInfo *package_data = NULL;
    
    if (response)
    {
        package_data = ParseAndCheckPackageDataReply(response, error);
        RlistDestroy(response);
    }
    free(options_str);
    free((void*)request);
        
    return package_data;
}

//TODO: implement me
static char *GetPackageWrapperRealPath(const char *package_manager_name)
{
    
    return strdup("/tmp/dummy");
}

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
        //FreePackageManageWrapper(wrapper);
        //return NULL;
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

PromiseResult HandleAbsentPromiseAction(const char *package_name,
                          const NewPackages *new_packages,
                          const PackageManagerWrapper *wrapper)
{
    /* Check if package exists in cache */
    //TODO: ?
    
    
    return PROMISE_RESULT_NOOP;
}

PromiseResult InstallPackage(Rlist *options, 
        PackageType type, const char *package_to_install,
        const PackageManagerWrapper *wrapper)
{
    char *options_str = ParseOptions(options);
    char *request = StringFormat("%sFile=%s\n",
                                 options_str, package_to_install);
    
    //TODO: figure out result
    PromiseResult res = PROMISE_RESULT_CHANGE;
    
    const char *package_install_command = NULL;
    if (type == PACKAGE_TYPE_FILE)
    {
        package_install_command = "file-install";
    }
    else if (type == PACKAGE_TYPE_REPO)
    {
        package_install_command = "repo-install";
    }
    else
    {
        /* If we end up here something bad has happened. */
        assert(0 && "unsupported package type");
    }
    
    if (WriteDataToPackageScript(package_install_command, request, wrapper) != 0)
    {
        Log(LOG_LEVEL_VERBOSE,
            "error installing package");
        res = PROMISE_RESULT_FAIL;
    }
    
    free(request);
    free(options_str);
    
    /* We assume that at this point package is installed correctly. */
    return res;
}

PromiseResult FileInstallPackage(const char *package_file_path, 
        const NewPackages *new_packages, PackageInfo *info,
        const PackageManagerWrapper *wrapper)
{
    Log(LOG_LEVEL_ERR, "FILE INSTALL PACKAGE");
    
    /* First check if file we are having matches what we want in policy. */
    if (info->arch && new_packages->package_architecture && 
            !StringSafeEqual(info->arch, new_packages->package_architecture))
    {
        Log(LOG_LEVEL_ERR, 
            "package arch and one specified in policy doesn't match: %s -> %s",
            info->arch, new_packages->package_architecture);
        //TODO: figure out results!
        return PROMISE_RESULT_FAIL;
    }
    if (info->version && new_packages->package_version && 
            (!StringSafeEqual(new_packages->package_version, "latest") ||
             !StringSafeEqual(info->arch, new_packages->package_architecture)))
    {
        Log(LOG_LEVEL_ERR,
            "package version and one specified in policy doesn't match: %s -> %s",
            info->version, new_packages->package_version);
        //TODO: figure out results!
        return PROMISE_RESULT_FAIL;
    }
    
    return InstallPackage(new_packages->package_options, PACKAGE_TYPE_FILE,
            package_file_path, wrapper);
}

PromiseResult RepoInstallPackage(const PackageInfo *package_info,
        const NewPackages *policy_data, const PackageManagerWrapper *wrapper)
{
    Log(LOG_LEVEL_ERR, "REPO INSTALL PACKAGE");
    
    /* Check if policy is latest and if so get possible package form updates. */
    if (policy_data->package_version &&
        StringSafeEqual(policy_data->package_version, "latest"))
    {
        //TODO: check last package version
        //package_info->version = //one from updates
    }
    
    return InstallPackage(policy_data->package_options, PACKAGE_TYPE_REPO,
            package_info->name, wrapper);
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
        /* Check if package exists in cache */
        //TODO:
        
        switch (package_info->type)
        {
            case PACKAGE_TYPE_FILE:
                result = FileInstallPackage(package_name,
                                            new_packages, package_info,
                                            package_manager_wrapper);
                
                if (result == PROMISE_RESULT_CHANGE)
                {
                    //TODO: run 'list-installed' and see if package is there
                    //TODO: update cache
                }
                break;
            case PACKAGE_TYPE_REPO:
                result = RepoInstallPackage(package_info, new_packages,
                                            package_manager_wrapper);
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
    else if (error.type)
    {
        if (error.message)
        {
            Log(LOG_LEVEL_ERR, "have error: %s [%s]", error.type, error.message);
            free(error.message);
        }
        else
        {
            Log(LOG_LEVEL_ERR, "have error: %s", error.type);
        }
        free(error.type);
    }
    Log(LOG_LEVEL_ERR, "PRESENT PROMISE ACTION RETURNES: %c", result);
    return result;
}

PromiseResult HandleNewPackagePromiseType(EvalContext *ctx, const Promise *pp, Attributes *a)
{
    Log(LOG_LEVEL_ERR, "New package promise handler");
    //TODO: sanity check
    
    char *package_manager = a->new_packages.package_manager;
    if (!package_manager)
    {
        /* Get default package manager from system */
        //TODO: implement me
        package_manager = strdup("apt-get");
    }

    PromiseBanner(ctx, pp);
    
    //TODO: lock
    
    PackageManagerWrapper *package_manager_wrapper =
            GetPackageManagerWrapper(package_manager);
    
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
