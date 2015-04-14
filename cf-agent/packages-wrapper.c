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

int WriteDataToPackageScript(const char *data, const IOData *io)
{
    ssize_t wrt = write(io->write_fd, data, strlen(data));
    
    return wrt;
}

Rlist *ReadWriteDataToPackageScript(const char *write_buff, const IOData *io)
{
    if (WriteDataToPackageScript(write_buff, io) != strlen(write_buff))
    {
        Log(LOG_LEVEL_ERR, "couldn't write whole data to script");
        return NULL;
    }
    
    return RedDataFromPackageScript(io);
}


static int NegotiateSupportedAPIVersion(PackageManagerWrapper *wrapper)
{
    IOData io = cf_popen_full_duplex(wrapper->path, true);
    int api_version = -1;

    if (io.write_fd == 0 || io.read_fd == 0)
    {
        Log(LOG_LEVEL_VERBOSE, "some error occurred while negotiating API version");
        return -1;
    }
   Log(LOG_LEVEL_ERR, "IO: %d %d", io.write_fd, io.read_fd);

    Rlist *response = ReadWriteDataToPackageScript("supports-api-version\n", &io);
    
    if (response)
    {
        if (RlistLen(response) == 1)
        {
            api_version = atoi(RlistScalarValue(response));
            Log(LOG_LEVEL_ERR, "package wrapper API version: %d", api_version);
        }
        RlistDestroy(response);
    }
    
    /* If script returns non 0 exit code */
    if (cf_pclose_full_duplex(&io) != 0)
    {
        Log(LOG_LEVEL_VERBOSE,
            "some error occurred while closing communication channel");
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
PackageInfo *ParseAndCheckPackageDataReply(const Rlist *data)
{
    PackageInfo *package_data = xcalloc(1, sizeof(PackageInfo));
    
    for (const Rlist *rp = data; rp != NULL; rp = rp->next)
    {
        char *line = RlistScalarValue(rp);
                   
        if (StringStartsWith(line, "PackageType"))
        {
            //TODO: extra check if line + strlen(get_package_attributes[0]) == '=' ?
            char *type = line + strlen("PackageType") + 1;
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
        else if (StringStartsWith(line, "Name"))
        {
            package_data->name = 
                SafeStringDuplicate(line + strlen("Name") + 1);
        }
        else if (StringStartsWith(line, "Version"))
        {
            package_data->version = 
                SafeStringDuplicate(line + strlen("Version") + 1);
        }
        else if (StringStartsWith(line, "Architecture"))
        {
            package_data->arch = 
                SafeStringDuplicate(line + strlen("Architecture") + 1);
        }
        else
        {
            Log(LOG_LEVEL_ERR, "unsupported option: %s", line);
        }
    }
    
    /* At this point at least package name MUST be known */
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
                            const PackageManagerWrapper *wrapper)
{
    IOData io = cf_popen_full_duplex(wrapper->path, true);
    if (io.write_fd == 0 || io.read_fd == 0)
    {
        Log(LOG_LEVEL_ERR, "some error occurred while negotiating API version");
        return NULL;
    }
     Log(LOG_LEVEL_ERR, "IO: %d %d", io.write_fd, io.read_fd);
    
    char *options_str = ParseOptions(options);
    char *request = StringFormat("get-package-data\n%sFile=%s\n",
                                 options_str, name);
    
    Rlist *response = ReadWriteDataToPackageScript(request, &io);
    PackageInfo *package_data = NULL;
    
    if (response)
    {
        package_data = ParseAndCheckPackageDataReply(response);
        RlistDestroy(response);
    }
    free(options_str);
    free(request);
    
    /* If script returns non 0 exit code */
    if (cf_pclose_full_duplex(&io) != 0)
    {
        Log(LOG_LEVEL_VERBOSE,
            "some error occurred while closing communication channel");
    }
    
    return package_data;
}

//TODO: implement me
static char *GetPackageWrapperRealPath(const char *package_manager_name)
{
    
    return strdup("/usr/bin/python /tmp/dummy");
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

PromiseResult FileInstallPackage(const char *package_file_path, Rlist *options,
                       const PackageManagerWrapper *wrapper)
{
    Log(LOG_LEVEL_ERR, "FILE INSTALL PACKAGE");
    IOData io = cf_popen_full_duplex(wrapper->path, true);
    if (io.write_fd == 0 || io.read_fd == 0)
    {
        Log(LOG_LEVEL_ERR, "some error occurred while negotiating API version");
        return PROMISE_RESULT_FAIL;
    }
     Log(LOG_LEVEL_ERR, "IO: %d %d", io.write_fd, io.read_fd);
    
    char *options_str = ParseOptions(options);
    char *request = StringFormat("file-install\n%sFile=%s\n",
                                 options_str, package_file_path);
    
    WriteDataToPackageScript(request, &io);
    
    /* If script returns non 0 exit code */
    if (cf_pclose_full_duplex(&io) != 0)
    {
        Log(LOG_LEVEL_VERBOSE,
            "some error occurred while closing communication channel");
        return PROMISE_RESULT_FAIL;
    }
    
    /* We assume that at this point package is installed correctly. */
    return PROMISE_RESULT_CHANGE;
}

PromiseResult RepoInstallPackage(const PackageInfo *package_info, Rlist *options,
                       const PackageManagerWrapper *wrapper)
{
    Log(LOG_LEVEL_ERR, "REPO INSTALL PACKAGE");
    return PROMISE_RESULT_NOOP;
}

PromiseResult HandlePresentPromiseAction(const char *package_name,
                           const NewPackages *new_packages,
                           const PackageManagerWrapper *package_manager_wrapper)
{
    Log(LOG_LEVEL_ERR, "PRESENT PROMISE ACTION");
    /* Figure out what kind of package we are having. */
    PackageInfo *package_info = GetPackageData(package_name,
                                               new_packages->package_options,
                                               package_manager_wrapper);
    
    PromiseResult result = PROMISE_RESULT_FAIL;
    if (package_info)
    {
        /* Check if package exists in cache */
        //TODO:
        
        switch (package_info->type)
        {
            case PACKAGE_TYPE_FILE:
                result = FileInstallPackage(package_name,
                                            new_packages->package_options,
                                            package_manager_wrapper);
                
                if (result == PROMISE_RESULT_CHANGE)
                {
                    //TODO: run 'list-installed' and see if package is there
                    //TODO: update cache
                }
                break;
            case PACKAGE_TYPE_REPO:
                result = RepoInstallPackage(package_info,
                                            new_packages->package_options,
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
