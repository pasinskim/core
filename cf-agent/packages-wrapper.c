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

static 
int IsReadWriteReady(IOData *io, int timeout_sec)
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

int RedDataFromPackageScript(char **read_buffer, IOData *io)
{
    char buff[CF_BUFSIZE] = {0};
    int red_data_size = 0;
    
    while(!IsPendingTermination())
    {
        int fd = IsReadWriteReady(io, PACKAGE_PROMISE_SCRIPT_TIMEOUT_SEC);
        
        if (fd <= 0)
        {
            Log(LOG_LEVEL_ERR, 
                "error reading data from package wrapper script: %s",
                GetErrorStr());
            return -1;
        }
        else if (fd == io->read_fd)
        {
            ssize_t res = read(fd, buff + red_data_size, sizeof(buff) - red_data_size - 1);
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
                    return -1;
                }
            }
            else if (res == 0) /* reached EOF */
            {
                break;
            }
             Log(LOG_LEVEL_ERR, "red: %d [%s]", res, buff);
             red_data_size += res;
             //TODO: copy data to some external buffer
        }
    }
    *read_buffer = strdup(buff);
    return red_data_size;
}

int WriteDataToPackageScript(char *read_buffer, IOData *io)
{
    ssize_t wrt = write(io->write_fd, read_buffer, strlen(read_buffer));
    
    return wrt;
}

/* Might be extended in future if we will need real version negotiation. */
static int NegotiateSupportedAPIVersion(PackageManagerWrapper *wrapper)
{
    

    IOData io = cf_popen_full_duplex(wrapper->path, true);

    if (io.write_fd == 0 || io.read_fd == 0)
    {
        Log(LOG_LEVEL_VERBOSE, "some error occurred while negotiating API version");
        return -1;
    }
    
    WriteDataToPackageScript("ala ma kota", &io);
    
    char *buff;
    int red = RedDataFromPackageScript(&buff, &io);
    
    Log(LOG_LEVEL_ERR, "have some data: %d [%s]", red, buff);
    
    if (red > 0)
    {
        free(buff);
    }
    
    /* If script returns non 0 exit code */
    if (cf_pclose_full_duplex(&io) != 0)
    {
        Log(LOG_LEVEL_VERBOSE,
            "some error occurred while closing communication channel");
    }
    return 1;
}

//TODO: implement me
static const char *GetPackageWrapperRealPath(const char *package_manager_name)
{
    return "/usr/bin/python /tmp/dummy";
}

void FreePackageManageWrapper(PackageManagerWrapper *wrapper)
{
    free(wrapper->path);
    
    free(wrapper);
}

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
        //FreePackageManageWrapper(wrapper);
        //return NULL;
    }
    
    /* Negotiate API version */
    wrapper->supported_api_version = NegotiateSupportedAPIVersion(wrapper);
    if (wrapper->supported_api_version == -1)
    {
        FreePackageManageWrapper(wrapper);
        return NULL;
    }
    
    return wrapper;
}



