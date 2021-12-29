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

#define _GNU_SOURCE

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <zlib.h>

#include <libafb/sys/verbose.h>
#include "glue-utils.h"

// execute callback for each json array
int utilScanJson (json_object *sourceJ, utilScanJsonCbT callback, void *context) {
    int status;

    // if not source silently ignore
    if (!sourceJ) return 0;

    if (json_object_is_type(sourceJ, json_type_array)) {
        for (int idx=0; idx < json_object_array_length(sourceJ); idx++) {
            status= callback (json_object_array_get_idx (sourceJ, idx), context);
            if (status) break;
        }

    } else {
        status= callback (sourceJ, context);
    }
    return status;
}

// search for key label within key/value array
int utilLabel2Value (const nsKeyEnumT *keyvals, const char *label) {
    int idx;
    if (!label) goto OnDefaultExit;

    for (idx=0; keyvals[idx].label; idx++) {
        if (!strcasecmp (label,keyvals[ idx].label)) break;
    }
    return keyvals[idx].value;

OnDefaultExit:
    return keyvals[0].value;
}

// search for key label within key/value array
const char* utilValue2Label (const nsKeyEnumT *keyvals, const int value) {
    const char *label=NULL;

    for (int idx=0; keyvals[idx].label; idx++) {
        if (keyvals[ idx].value == value) {
            label= keyvals[idx].label;
            break;
        }
    }
    return label;
}

int utilFileLoad (const char *filepath, char **response) {
    int err;
    struct stat statbuf;
    char *buffer;

    err = stat(filepath, &statbuf);
    if (err < 0 || !(statbuf.st_mode & S_IREAD)) {
        goto OnErrorExit;
    }

    // allocate filesize buffer
    buffer = malloc(statbuf.st_size+1);
    if (! buffer) goto OnErrorExit;

    // open file in readonly
    int fdFile = open (filepath, O_RDONLY);
    if (fdFile <0) goto OnErrorExit;

    ssize_t count=0, len;
    do {
        len= read(fdFile, &buffer[count], statbuf.st_size-count);
        if (len >0) count += len;
    } while (len < 0 && errno == EINTR);
    close (fdFile);
    buffer[count]='\0'; // close string

    *response=buffer;
    return (int)count;

OnErrorExit:
    return -1;
}

char *utilStr2Token (str2TokenT *handle, u_int8_t separator, const char* data) {

    // on 1st call separator should be defined
    if (data) {
        handle->str=NULL;
        if (!separator) goto OnErrorExit;
        handle->str= strdup(data);
        handle->sep = separator;
        handle->index=0;
    } else {
        // no more data
        if (!handle->str[handle->index]) goto OnErrorExit;
    }

    size_t idx, onsep=0;
    char* token;

    for (idx=handle->index; handle->str[idx] != '\0'; idx ++) {
        if (handle->str[idx] == handle->sep) {
            handle->str[idx]='\0';
            onsep=1;
            break;
        }
    }
    token=&handle->str[handle->index];
    if (onsep) handle->index= idx+1;
    else handle->index=idx;

    return token;

OnErrorExit:
    if (handle->str) free (handle->str);
    return NULL;
}

int utilFdToPath (int fileFd, char *pathname, size_t maxLen) {
    char fileproc [UTILS_MAX_FDPATH_LEN];
    size_t pathlen;

    // use '/proc/pid/fd/xx' to retreive a full relpath
    snprintf (fileproc, sizeof(fileproc), "/proc/%d/fd/%d", getpid(), fileFd);
    pathlen= readlink(fileproc, pathname, maxLen);
    pathname[pathlen]='\0';
    if (pathlen == (size_t)-1 || pathlen == maxLen) goto OnErrorExit;

    return 0;

OnErrorExit:
    ERROR ("FdToPath Fail to open %s error=%s", fileproc, strerror(errno));
    return -1;
}

// check if relpath maches the extention
int utilMatchExtention (const char *relpath, const char *extention) {
    int index;

    // no extention always valid
    if (!extention) return 1;

    for (index=0; relpath[index] != '\0'; index ++) {
        if (relpath[index] == extention[0])  break;
    }

    // '.' not found within relpath
    if (relpath[index] != extention[0]) goto OnErrorExit;

    // check extention matched
    if (strcmp (&relpath[index], extention)) goto OnErrorExit;

    return 1;

OnErrorExit:
    return 0;
}

static int FdCallbackExec (int dirFd, const char *relpath, utilScanDirCbT callback,  uint32_t flags, uint32_t ftype, void *context) {
    int err;
    int fileFd;
    char fullpath[UTILS_MAX_FDPATH_LEN];

    if (flags & SCANDIR_FULLNAME) {
        fileFd= openat (dirFd, relpath, O_RDONLY);
        if (fileFd < 0) goto OnErrorExit;

        err= utilFdToPath(fileFd, fullpath, sizeof(fullpath));
        close (fileFd); // fd not needed any more
        if (err < 0) goto OnErrorExit;

        err= callback (dirFd, fullpath, relpath, ftype, context);
    } else {
        err= callback (dirFd, relpath, relpath, ftype, context);
    }

    if (err < 0) goto OnErrorExit;
    if (err > 0) goto OnIgnoreExit;

    return 0;

OnIgnoreExit:
    err= utilFdToPath(dirFd, fullpath, sizeof(fullpath));
    if (err < 0) (void)strncmp (fullpath, "????", sizeof(fullpath));
    NOTICE ("FdScanDir: ignoring file=%s/%s", fullpath, relpath);
    return 1;

OnErrorExit:
    err= utilFdToPath(dirFd, fullpath, sizeof(fullpath));
    if (err <0) (void)strncmp (fullpath, "????", sizeof(fullpath));
    ERROR ("FdScanDir: fail on path=%s/%s error=%s", fullpath, relpath, strerror(errno));
    return -1;
}
static int FdScanDir(int dirFd, const char *relpath, const char* filter, utilScanDirCbT callback,  uint32_t flags, void *context) {
    struct dirent* dirEnt;
    DIR *dirHandle;

    if (! (flags & SCANDIR_GET_ALL) && relpath[0] == '_') goto OnIgnoreExit;

    // open directory and keep track for its FD for openat function
    dirHandle= fdopendir(dirFd);
    if (!dirHandle) {
        ERROR ("FdScanDir: Fail to open dir=%s error=%s", relpath, strerror(errno));
        goto OnErrorExit;
    }

    //NOTICE ("CONFIG-SCANNING:ctl_listconfig scanning: %s", relpath);
    while ((dirEnt = readdir(dirHandle)) != NULL) {
        int err;

        // recursively search embedded directories ignoring any directory starting by '.'
        switch (dirEnt->d_type) {
            case DT_DIR: {
                if (dirEnt->d_name[0] == '.' ) continue;

                int newFd= openat (dirFd, dirEnt->d_name, O_RDONLY);
                if (newFd < 0) {
                    ERROR("FdScanDir Fail to read dir dir=%s entry=%s error=%s", relpath, dirEnt->d_name, strerror(errno));
                    goto OnErrorExit;
                }
                err = FdScanDir(newFd, dirEnt->d_name, filter, callback, flags, context);
                if (err) goto OnErrorExit;
                if (flags & SCANDIR_CALL_ALL) {
                    err= FdCallbackExec (dirFd, dirEnt->d_name, callback,  flags, SCANDIR_IS_DIR, context);
                    if (err < 0) goto OnErrorExit;
                }
                break;
            }

            case DT_REG:
            case DT_LNK:
                // ignore any file without .mbtiles extention
                if (!utilMatchExtention (dirEnt->d_name, filter)) {
                    DEBUG ("FdScanDir: ignored entry=%s", dirEnt->d_name);
                    continue;
                }

                err= FdCallbackExec (dirFd, dirEnt->d_name, callback,  flags, SCANDIR_IS_FILE, context);
                if (err < 0) goto OnErrorExit;
                break;

            default:
                ERROR("FdScanDir Fail to unlink file dir=%s file=%s unsupported file type", relpath, dirEnt->d_name);
                goto OnErrorExit;

        }
    }
    closedir(dirHandle);
    return 0;

OnIgnoreExit:
    DEBUG ("FdScanDir: ignored relpath=%s", relpath);
    return 1;

OnErrorExit:
    if (dirHandle) closedir(dirHandle);
    return -1;
}


int utilScanDir (const char* relpath, const char * filter, utilScanDirCbT callback,  uint32_t flags, void *context) {
    int pathFd, err;
    struct stat statbuf;

    pathFd= open(relpath, O_RDONLY);
    if (pathFd <0) {
        ERROR ("ScanDir Fail to open dir=%s error=%s", relpath, strerror(errno));
        goto NoDirExit;
    }

    err= fstat(pathFd, &statbuf);
    if (err < 0) {
        ERROR ("ScanDir Fail to stat dir=%s error=%s", relpath, strerror(errno));
        goto OnErrorExit;
    }

    if (S_ISDIR (statbuf.st_mode)) {
        err= FdScanDir(pathFd, relpath, filter, callback, flags, context);
        if (err < 0) {
            close (pathFd);
            goto OnErrorExit;
        }

    } else {
        err= FdCallbackExec (pathFd, relpath, callback,  flags, SCANDIR_IS_FILE, context);
        if (err < 0) {
            ERROR("ScanDir Fail callback file=%s error=%s", relpath, strerror(errno));
            goto OnErrorExit;
        }
    }

    close (pathFd);
    return 0;

NoDirExit:
    return 1;

OnErrorExit:
    return -1;
}

// fork version of zlib version to support gzip format
static int utilGunzip2 (Bytef *dest, uLongf *destLen, const Bytef *source, uLong *sourceLen) {
    z_stream stream;
    int err;
    const uInt max = (uInt)-1;
    uLong len, left;
    Byte buf[1];    /* for detection of incomplete stream when *destLen == 0 */

    len = *sourceLen;
    if (*destLen) {
        left = *destLen;
        *destLen = 0;
    }
    else {
        left = 1;
        dest = buf;
    }

    stream.next_in = (z_const Bytef *)source;
    stream.avail_in = 0;
    stream.zalloc = (alloc_func)0;
    stream.zfree = (free_func)0;
    stream.opaque = (voidpf)0;

    err = inflateInit2(&stream, 16+MAX_WBITS);
    if (err != Z_OK) return err;

    stream.next_out = dest;
    stream.avail_out = 0;

    do {
        if (stream.avail_out == 0) {
            stream.avail_out = left > (uLong)max ? max : (uInt)left;
            left -= stream.avail_out;
        }
        if (stream.avail_in == 0) {
            stream.avail_in = len > (uLong)max ? max : (uInt)len;
            len -= stream.avail_in;
        }
        err = inflate(&stream, Z_NO_FLUSH);
    } while (err == Z_OK);

    *sourceLen -= len + stream.avail_in;
    if (dest != buf)
        *destLen = stream.total_out;
    else if (stream.total_out && err == Z_BUF_ERROR)
        left = 1;

    inflateEnd(&stream);
    return err == Z_STREAM_END ? Z_OK :
           err == Z_NEED_DICT ? Z_DATA_ERROR  :
           err == Z_BUF_ERROR && left + stream.avail_out ? Z_DATA_ERROR :
           err;
}

int utilGunzip (uint8_t *dest, size_t *destLen, const uint8_t *source, size_t sourceLen) {
    static nsKeyEnumT zErrors[]= {
        {"Z_UNKNOWN", 0},
        {"Z_STREAM_END"   , Z_STREAM_END},
        {"Z_NEED_DICT"    , Z_NEED_DICT},
        {"Z_ERRNO"        , Z_ERRNO},
        {"Z_STREAM_ERROR" , Z_STREAM_ERROR},
        {"Z_DATA_ERROR"   , Z_DATA_ERROR},
        {"Z_MEM_ERROR"    , Z_MEM_ERROR},
        {"Z_BUF_ERROR"    , Z_BUF_ERROR},
        {"Z_VERSION_ERROR", Z_VERSION_ERROR},
        {NULL}
    };

    int err= utilGunzip2 (dest, destLen, source, &sourceLen);
    if (err != Z_OK) {
        ERROR ("[utilGunzip fail uncompressing gzip err=%s]", utilValue2Label(zErrors, err));
    }

    return err;
}
