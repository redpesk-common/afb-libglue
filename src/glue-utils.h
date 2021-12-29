/*
 * Copyright (C) 2015-2021 IoT.bzh Company
 * Author "Fulup Ar Foll"
 *
 * $RP_BEGIN_LICENSE$
 * Commercial License Usage
 *  Licensees holding valid commercial IoT.bzh licenses may use this file in
 *  accordance with the commercial license agreement provided with the
 *  Software or, alternatively, in accordance with the terms contained in
 *  a written agreement between you and The IoT.bzh Company. For licensing terms
 *  and conditions see https://www.iot.bzh/terms-conditions. For further
 *  information use the contact form at https://www.iot.bzh/contact.
 *
 * GNU General Public License Usage
 *  Alternatively, this file may be used under the terms of the GNU General
 *  Public license version 3. This license is as published by the Free Software
 *  Foundation and appearing in the file LICENSE.GPLv3 included in the packaging
 *  of this file. Please review the following information to ensure the GNU
 *  General Public License requirements will be met
 *  https://www.gnu.org/licenses/gpl-3.0.html.
 * $RP_END_LICENSE$
*/

#pragma once

#include <json-c/json.h>

#ifndef UTILS_MAX_FDPATH_LEN
#define UTILS_MAX_FDPATH_LEN 512
#endif

typedef struct {
    const char *label;
    const int  value;
} nsKeyEnumT;

typedef struct {
    char *str;
    u_int8_t sep;
    size_t index;
} str2TokenT;

#define SCANDIR_FULLNAME    0x01
#define SCANDIR_BASENAME    0x02
#define SCANDIR_IS_DIR      0x04
#define SCANDIR_IS_FILE     0x08
#define SCANDIR_GET_ALL     0x10
#define SCANDIR_CALL_ALL    0x20

int utilLabel2Value (const nsKeyEnumT *keyvals, const char *label);
const char* utilValue2Label (const nsKeyEnumT *keyvals, const int value);

typedef int (*utilScanDirCbT)   (int dirFd, const char *fullname, const char *basename, uint32_t ftype, void *context);
typedef int (*utilScanJsonCbT) (json_object *sourceJ, void *context);

int utilScanJson (json_object *sourceJ, utilScanJsonCbT callback, void *context);

int utilScanDir (const char* path, const char *filter, utilScanDirCbT callback, uint32_t flags, void *context);
int utilFdToPath (int fileFd, char *pathname, size_t maxLen);
int utilMatchExtention (const char *relpath, const char *extention);
int utilFileLoad (const char *filepath, char **buffer);
int utilGunzip (uint8_t *dest, size_t *destLen, const uint8_t *source, size_t sourceLen);
char *utilStr2Token (str2TokenT *handle, u_int8_t separator, const char* data);
