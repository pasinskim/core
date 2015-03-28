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

#include <pipes.h>

#include <mutex.h>
#include <exec_tools.h>
#include <rlist.h>
#include <policy.h>
#include <eval_context.h>
#include <file_lib.h>

static int CfSetuid(uid_t uid, gid_t gid);

static int cf_pwait(pid_t pid);

static pid_t *CHILDREN = NULL; /* GLOBAL_X */
static int MAX_FD = 128; /* GLOBAL_X */ /* Max number of simultaneous pipes */

static int InitChildrenFD()
{
    if (!ThreadLock(cft_count))
    {
        return false;
    }

    if (CHILDREN == NULL)       /* first time */
    {
        CHILDREN = xcalloc(MAX_FD, sizeof(pid_t));
    }

    ThreadUnlock(cft_count);
    return true;
}

/*****************************************************************************/

static void CloseChildrenFD()
{
    ThreadLock(cft_count);
    int i;
    for (i = 0; i < MAX_FD; i++)
    {
        if (CHILDREN[i] > 0)
        {
            close(i);
        }
    }
    free(CHILDREN);
    CHILDREN = NULL;
    ThreadUnlock(cft_count);
}

/*****************************************************************************/

static void SetChildFD(int fd, pid_t pid)
{
    int new_max = 0;

    if (fd >= MAX_FD)
    {
        Log(LOG_LEVEL_WARNING,
            "File descriptor %d of child %jd higher than MAX_FD, check for defunct children",
            fd, (intmax_t) pid);
        new_max = fd + 32;
    }

    ThreadLock(cft_count);

    if (new_max)
    {
        CHILDREN = xrealloc(CHILDREN, new_max * sizeof(pid_t));
        MAX_FD = new_max;
    }

    CHILDREN[fd] = pid;
    ThreadUnlock(cft_count);
}

/*****************************************************************************/

typedef struct
{
    const char *type;
    int pipe_desc[2];
} IOPipe;

static pid_t GenericCreatePipeAndFork(IOPipe *pipes)
{
    for (int i = 0; i < 2; i++)
    {
        if (pipes[i].type && !PipeTypeIsOk(pipes[i].type))
        {
            errno = EINVAL;
            return -1;
        }
    }

    if (!InitChildrenFD())
    {
        return -1;
    }

    /* Create pair of descriptors to this process. */
    if (pipes[0].type && pipe(pipes[0].pipe_desc) < 0)
    {
        return -1;
    }
    
    /* Create second pair of descriptors (if exists) to this process.
     * This will allow full I/O operations. */
    if (pipes[1].type && pipe(pipes[1].pipe_desc) < 0)
    {
        close(pipes[0].pipe_desc[0]);
        close(pipes[0].pipe_desc[1]);
        return -1;
    }

    pid_t pid = -1;
    
    if ((pid = fork()) == -1)
    {
        /* One pipe will be always here. */
        close(pipes[0].pipe_desc[0]);
        close(pipes[0].pipe_desc[1]);
        
        /* Second pipe is optional so we have to check existence. */
        if (pipes[1].type)
        {
            close(pipes[1].pipe_desc[0]);
            close(pipes[1].pipe_desc[1]);
        }
        return -1;
    }

    signal(SIGCHLD, SIG_DFL);

    // Redmine #2971: reset SIGPIPE signal handler to have a sane behavior of piped commands within child
    if (pid == 0)
    {
        signal(SIGPIPE, SIG_DFL);
    }

    ALARM_PID = (pid != 0 ? pid : -1);

    return pid;
}

/*****************************************************************************/

static pid_t CreatePipeAndFork(const char *type, int *pd)
{
    IOPipe pipes[2] = {{0}};
    pipes[0].type = type;
    
    pid_t pid = GenericCreatePipeAndFork(pipes);
    
    pd[0] = pipes[0].pipe_desc[0];
    pd[1] = pipes[0].pipe_desc[1];

    return pid;
}

/*****************************************************************************/

static pid_t CreatePipesAndFork(const char *type, int *pd, int *pdb)
{
    IOPipe pipes[2] = {{0}};
    /* Both pipes MUST have the same type. */
    pipes[0].type = type;
    pipes[1].type = type;

    pid_t pid =  GenericCreatePipeAndFork(pipes);

    pd[0] = pipes[0].pipe_desc[0];
    pd[1] =  pipes[0].pipe_desc[1];
    pdb[0] = pipes[1].pipe_desc[0];
    pdb[1] = pipes[1].pipe_desc[1];
    return pid;
}

/*****************************************************************************/

IOData cf_popen_full_duplex(const char *command, bool capture_stderr)
{
/* For simplifying reading and writing directions */
#define READ  0
#define WRITE 1
    int child_pipe[2];  /* From child to parent */
    int parent_pipe[2]; /* From parent to child */
    pid_t pid;

    fflush(NULL); /* Empty file buffers */
    pid = CreatePipesAndFork("rt", child_pipe, parent_pipe);

    if (pid < 0)
    {
        Log(LOG_LEVEL_ERR, "Couldn't fork child process: %s", GetErrorStr());
        return (IOData) {0, 0};
    }
    
    else if (pid > 0) // parent
    {
        close(child_pipe[WRITE]);
        close(parent_pipe[READ]);
        
        IOData io_desc = {0};
        io_desc.write_fd = parent_pipe[WRITE];
        io_desc.read_fd = child_pipe[READ];
        
        SetChildFD(parent_pipe[WRITE], pid);
        SetChildFD(child_pipe[READ], pid);
        return io_desc;
    }
    else // child
    {
        int fd;

        close(child_pipe[READ]);
        close(parent_pipe[WRITE]);

        /* Open stdin from parant process and stdout from child */
        if (dup2(parent_pipe[READ], 0) == -1 || dup2(child_pipe[WRITE],1) == -1)
        {
            Log(LOG_LEVEL_ERR, "Can not execute dup2: %s", GetErrorStr());
            _Exit(EXIT_FAILURE);
        }
        
        if (capture_stderr)
        {
            /* Merge stdout/stderr */
            if(dup2(child_pipe[WRITE], 2) == -1)
            {
                Log(LOG_LEVEL_ERR, "Can not execute dup2 for merging stderr: %s", 
                    GetErrorStr());
                _Exit(EXIT_FAILURE);
            }
        }
        else
        {
            /* Close stderr */
            if ((fd = open(NULLFILE, O_WRONLY)) == -1 || (dup2(fd, 2) == -1))
            {
                Log(LOG_LEVEL_ERR, 
                    "Can not execute dup2 while closing stderr: %s",
                    GetErrorStr());
                _Exit(EXIT_FAILURE);
            }
            close(fd);
        }
        
        close(child_pipe[WRITE]);
        close(parent_pipe[READ]);

        CloseChildrenFD();
        
        char **argv  = ArgSplitCommand(command);
        if (execv(argv[0], argv) == -1)
        {
            /* NOTE: exec functions return only when error have occured. */
            Log(LOG_LEVEL_ERR, "Couldn't run '%s'. (execv: %s)", argv[0], GetErrorStr());
        }
        /* We shouldn't reach this point */
        _Exit(EXIT_FAILURE);
    }
}

FILE *cf_popen(const char *command, const char *type, bool capture_stderr)
{
    int pd[2];
    char **argv;
    pid_t pid;
    FILE *pp = NULL;

    pid = CreatePipeAndFork(type, pd);
    if (pid == -1) {
        return NULL;
    }

    if (pid == 0)
    {
        switch (*type)
        {
        case 'r':

            close(pd[0]);       /* Don't need output from parent */

            if (pd[1] != 1)
            {
                dup2(pd[1], 1); /* Attach pp=pd[1] to our stdout */

                if (capture_stderr)
                {
                    dup2(pd[1], 2); /* Merge stdout/stderr */
                }
                else
                {
                    int nullfd = open(NULLFILE, O_WRONLY);
                    dup2(nullfd, 2);
                    close(nullfd);
                }

                close(pd[1]);
            }

            break;

        case 'w':

            close(pd[1]);

            if (pd[0] != 0)
            {
                dup2(pd[0], 0);
                close(pd[0]);
            }
        }

        CloseChildrenFD();

        argv = ArgSplitCommand(command);

        if (execv(argv[0], argv) == -1)
        {
            Log(LOG_LEVEL_ERR, "Couldn't run '%s'. (execv: %s)", argv[0], GetErrorStr());
        }

        _exit(EXIT_FAILURE);
    }
    else
    {
        switch (*type)
        {
        case 'r':

            close(pd[1]);

            if ((pp = fdopen(pd[0], type)) == NULL)
            {
                cf_pwait(pid);
                return NULL;
            }
            break;

        case 'w':

            close(pd[0]);

            if ((pp = fdopen(pd[1], type)) == NULL)
            {
                cf_pwait(pid);
                return NULL;
            }
        }

        SetChildFD(fileno(pp), pid);
        return pp;
    }

    return NULL;                /* Cannot reach here */
}

/*****************************************************************************/

FILE *cf_popensetuid(const char *command, const char *type, uid_t uid, gid_t gid, char *chdirv, char *chrootv, ARG_UNUSED int background)
{
    int pd[2];
    char **argv;
    pid_t pid;
    FILE *pp = NULL;

    pid = CreatePipeAndFork(type, pd);
    if (pid == -1) {
        return NULL;
    }

    if (pid == 0)
    {
        switch (*type)
        {
        case 'r':

            close(pd[0]);       /* Don't need output from parent */

            if (pd[1] != 1)
            {
                dup2(pd[1], 1); /* Attach pp=pd[1] to our stdout */
                dup2(pd[1], 2); /* Merge stdout/stderr */
                close(pd[1]);
            }

            break;

        case 'w':

            close(pd[1]);

            if (pd[0] != 0)
            {
                dup2(pd[0], 0);
                close(pd[0]);
            }
        }

        CloseChildrenFD();

        argv = ArgSplitCommand(command);

        if (chrootv && (strlen(chrootv) != 0))
        {
            if (chroot(chrootv) == -1)
            {
                Log(LOG_LEVEL_ERR, "Couldn't chroot to '%s'. (chroot: %s)", chrootv, GetErrorStr());
                ArgFree(argv);
                return NULL;
            }
        }

        if (chdirv && (strlen(chdirv) != 0))
        {
            if (safe_chdir(chdirv) == -1)
            {
                Log(LOG_LEVEL_ERR, "Couldn't chdir to '%s'. (chdir: %s)", chdirv, GetErrorStr());
                ArgFree(argv);
                return NULL;
            }
        }

        if (!CfSetuid(uid, gid))
        {
            _exit(EXIT_FAILURE);
        }

        if (execv(argv[0], argv) == -1)
        {
            Log(LOG_LEVEL_ERR, "Couldn't run '%s'. (execv: %s)", argv[0], GetErrorStr());
        }

        _exit(EXIT_FAILURE);
    }
    else
    {
        switch (*type)
        {
        case 'r':

            close(pd[1]);

            if ((pp = fdopen(pd[0], type)) == NULL)
            {
                cf_pwait(pid);
                return NULL;
            }
            break;

        case 'w':

            close(pd[0]);

            if ((pp = fdopen(pd[1], type)) == NULL)
            {
                cf_pwait(pid);
                return NULL;
            }
        }

        SetChildFD(fileno(pp), pid);
        return pp;
    }

    return NULL;                /* cannot reach here */
}

/*****************************************************************************/
/* Shell versions of commands - not recommended for security reasons         */
/*****************************************************************************/

FILE *cf_popen_sh(const char *command, const char *type)
{
    int pd[2];
    pid_t pid;
    FILE *pp = NULL;

    pid = CreatePipeAndFork(type, pd);
    if (pid == -1) {
        return NULL;
    }

    if (pid == 0)
    {
        switch (*type)
        {
        case 'r':

            close(pd[0]);       /* Don't need output from parent */

            if (pd[1] != 1)
            {
                dup2(pd[1], 1); /* Attach pp=pd[1] to our stdout */
                dup2(pd[1], 2); /* Merge stdout/stderr */
                close(pd[1]);
            }

            break;

        case 'w':

            close(pd[1]);

            if (pd[0] != 0)
            {
                dup2(pd[0], 0);
                close(pd[0]);
            }
        }

        CloseChildrenFD();

        execl(SHELL_PATH, "sh", "-c", command, NULL);
        _exit(EXIT_FAILURE);
    }
    else
    {
        switch (*type)
        {
        case 'r':

            close(pd[1]);

            if ((pp = fdopen(pd[0], type)) == NULL)
            {
                cf_pwait(pid);
                return NULL;
            }
            break;

        case 'w':

            close(pd[0]);

            if ((pp = fdopen(pd[1], type)) == NULL)
            {
                cf_pwait(pid);
                return NULL;
            }
        }

        SetChildFD(fileno(pp), pid);
        return pp;
    }

    return NULL;
}

/******************************************************************************/

FILE *cf_popen_shsetuid(const char *command, const char *type, uid_t uid, gid_t gid, char *chdirv, char *chrootv, ARG_UNUSED int background)
{
    int pd[2];
    pid_t pid;
    FILE *pp = NULL;

    pid = CreatePipeAndFork(type, pd);
    if (pid == -1) {
        return NULL;
    }

    if (pid == 0)
    {
        switch (*type)
        {
        case 'r':

            close(pd[0]);       /* Don't need output from parent */

            if (pd[1] != 1)
            {
                dup2(pd[1], 1); /* Attach pp=pd[1] to our stdout */
                dup2(pd[1], 2); /* Merge stdout/stderr */
                close(pd[1]);
            }

            break;

        case 'w':

            close(pd[1]);

            if (pd[0] != 0)
            {
                dup2(pd[0], 0);
                close(pd[0]);
            }
        }

        CloseChildrenFD();

        if (chrootv && (strlen(chrootv) != 0))
        {
            if (chroot(chrootv) == -1)
            {
                Log(LOG_LEVEL_ERR, "Couldn't chroot to '%s'. (chroot: %s)", chrootv, GetErrorStr());
                return NULL;
            }
        }

        if (chdirv && (strlen(chdirv) != 0))
        {
            if (safe_chdir(chdirv) == -1)
            {
                Log(LOG_LEVEL_ERR, "Couldn't chdir to '%s'. (chdir: %s)", chdirv, GetErrorStr());
                return NULL;
            }
        }

        if (!CfSetuid(uid, gid))
        {
            _exit(EXIT_FAILURE);
        }

        execl(SHELL_PATH, "sh", "-c", command, NULL);
        _exit(EXIT_FAILURE);
    }
    else
    {
        switch (*type)
        {
        case 'r':

            close(pd[1]);

            if ((pp = fdopen(pd[0], type)) == NULL)
            {
                cf_pwait(pid);
                return NULL;
            }
            break;

        case 'w':

            close(pd[0]);

            if ((pp = fdopen(pd[1], type)) == NULL)
            {
                cf_pwait(pid);
                return NULL;
            }
        }

        SetChildFD(fileno(pp), pid);
        return pp;
    }

    return NULL;
}

static int cf_pwait(pid_t pid)
{
    int status;

    Log(LOG_LEVEL_DEBUG, "cf_pwait - Waiting for process %jd", (intmax_t)pid);

    while (waitpid(pid, &status, 0) < 0)
    {
        if (errno != EINTR)
        {
            return -1;
        }
    }

    if (!WIFEXITED(status))
    {
        return -1;
    }

    return WEXITSTATUS(status);
}

/*******************************************************************/

int PipeCloseGeneric(int pipes[2])
{
    if (!ThreadLock(cft_count))
    {
        close(pipes[0]);
        if (pipes[1] != 0)
        {
            close(pipes[1]);
        }
        return -1;
    }

    if (CHILDREN == NULL)       /* popen hasn't been called */
    {
        ThreadUnlock(cft_count);
        close(pipes[0]);
        if (pipes[1] != 0)
        {
            close(pipes[1]);
        }
        return -1;
    }

    ALARM_PID = -1;
    pid_t pid = 0;

    /* Safe as pipes[1] is 0 if not initialized */
    if (pipes[0] >= MAX_FD || pipes[1] >= MAX_FD)
    {
        ThreadUnlock(cft_count);
        Log(LOG_LEVEL_ERR,
            "File descriptor %d of child higher than MAX_FD in cf_pclose!",
            pipes[0] > pipes[1] ? pipes[0] : pipes[1]);
    }
    else
    {
        pid = CHILDREN[pipes[0]];
        if (pipes[1] != 0)
        {
            assert(pid == CHILDREN[pipes[1]]);
            CHILDREN[pipes[1]] = 0;
        }
        CHILDREN[pipes[0]] = 0;
        ThreadUnlock(cft_count);
    }
    
    if (close(pipes[0]) != 0 || (pipes[1] != 0 && close(pipes[1]) != 0) || pid == 0)
    {
        return -1;
    }

    return cf_pwait(pid);
}

int cf_pclose(FILE *pp)
{
    int fd = fileno(pp);
    return PipeCloseGeneric((int[2]){fd, 0});
}

int cf_pclose_full_duplex(IOData *data)
{
    return PipeCloseGeneric((int[2]){data->read_fd, data->write_fd});
}

bool PipeToPid(pid_t *pid, FILE *pp)
{
    int fd = fileno(pp);
    if (!ThreadLock(cft_count))
    {
        return false;
    }

    if (CHILDREN == NULL)       /* popen hasn't been called */
    {
        ThreadUnlock(cft_count);
        return false;
    }

    *pid = CHILDREN[fd];
    ThreadUnlock(cft_count);

    return true;
}

/*******************************************************************/

static int CfSetuid(uid_t uid, gid_t gid)
{
    struct passwd *pw;

    if (gid != (gid_t) - 1)
    {
        Log(LOG_LEVEL_VERBOSE, "Changing gid to %ju", (uintmax_t)gid);

        if (setgid(gid) == -1)
        {
            Log(LOG_LEVEL_ERR, "Couldn't set gid to '%ju'. (setgid: %s)", (uintmax_t)gid, GetErrorStr());
            return false;
        }

        /* Now eliminate any residual privileged groups */

        if ((pw = getpwuid(uid)) == NULL)
        {
            Log(LOG_LEVEL_ERR, "Unable to get login groups when dropping privilege to '%jd'. (getpwuid: %s)", (uintmax_t)uid, GetErrorStr());
            return false;
        }

        if (initgroups(pw->pw_name, pw->pw_gid) == -1)
        {
            Log(LOG_LEVEL_ERR, "Unable to set login groups when dropping privilege to '%s=%ju'. (initgroups: %s)", pw->pw_name,
                  (uintmax_t)uid, GetErrorStr());
            return false;
        }
    }

    if (uid != (uid_t) - 1)
    {
        Log(LOG_LEVEL_VERBOSE, "Changing uid to '%ju'", (uintmax_t)uid);

        if (setuid(uid) == -1)
        {
            Log(LOG_LEVEL_ERR, "Couldn't set uid to '%ju'. (setuid: %s)", (uintmax_t)uid, GetErrorStr());
            return false;
        }
    }

    return true;
}

