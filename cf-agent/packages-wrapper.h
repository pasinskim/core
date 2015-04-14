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

#ifndef PACKAGES_WRAPPER_H
#define PACKAGES_WRAPPER_H

#include <cf3.defs.h>

typedef enum
{
    PACKAGE_TYPE_REPO,
    PACKAGE_TYPE_FILE
} PackageType;

typedef struct 
{
    const char *name;
    const char *version;
    const char *arch;
    PackageType type;
} PackageInfo;

typedef struct
{
    char *name;
    char *path;
    int supported_api_version;
    
    PackageInfo* (*GetPackageInfo)(const char*);
    int (*InstallPackage)(PackageInfo*);
    
} PackageManagerWrapper;

PromiseResult HandleNewPackagePromiseType(EvalContext *ctx, const Promise *pp, Attributes *a);

#endif
