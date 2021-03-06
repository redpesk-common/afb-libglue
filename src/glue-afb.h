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
#include <libafb/afb-v4.h>

typedef enum {
    GLUE_NO_ARG=0,
    GLUE_ONE_ARG=1,
    GLUE_TWO_ARG=2,
    GLUE_THREE_ARG=3,
    GLUE_FOUR_ARG=4,
    GLUE_FIVE_ARG=5,
    GLUE_SIX_ARG=6,
} GlueNumArgs;

typedef enum {
    GLUE_UNKNOWN=0,
    GLUE_BINDER_MAGIC,
    GLUE_API_MAGIC,
    GLUE_RQT_MAGIC,
    GLUE_EVT_MAGIC,
    GLUE_TIMER_MAGIC,
    GLUE_JOB_MAGIC,
    GLUE_POST_MAGIC,
    GLUE_CALL_MAGIC,
} GlueHandleMagicsE;

typedef struct {
    void* magic;
    json_object *configJ;
    const char *uid;
    void *callback;
    void *thread;
    void *userdata;
    void *state;
} AfbVcbDataT;

const char * AfbMagicToString (GlueHandleMagicsE magic);
typedef struct AfbBinderHandleS AfbBinderHandleT;
typedef int (*AfbStartupCb) (void *config, void *context);
void GluePollRunJobs(void);

const char* AfbBinderConfig(json_object *configJ, AfbBinderHandleT **handle, void* userdata);
const char* AfbBindingLoad (AfbBinderHandleT *binder, json_object *bindingJ);
const char* AfbApiImport (AfbBinderHandleT *binder, json_object *configJ);
const char* AfbApiCreate   (AfbBinderHandleT *binder, json_object *configJ, afb_api_t *afbApi, afb_api_callback_t usrApiCb, afb_req_callback_x4_t usrInfoCb, afb_req_callback_x4_t usrRqtCb, afb_event_handler_x4_t usrEvtCb, void *userData);
int AfbBinderStart (AfbBinderHandleT *binder, void *config, AfbStartupCb callback, void *context);
int AfbBinderEnter (AfbBinderHandleT *binder, void *config, AfbStartupCb callback, void *context);
void AfbBinderExit(AfbBinderHandleT *binder, int exitcode);
int AfbBinderGetLogMask(AfbBinderHandleT *binder);
afb_api_t AfbBinderGetApi (AfbBinderHandleT *binder);

const char* AfbAddVerbs (AfbBinderHandleT *binder, afb_api_t apiv4, json_object *configJ, afb_req_callback_t callback);
const char* AfbAddOneVerb (AfbBinderHandleT *binder, afb_api_t apiv4, json_object *configJ, afb_req_callback_t callback, void *vcbData);
const char* AfbAddEvents (afb_api_t apiv4, json_object *configJ, afb_event_handler_t callback);
const char* AfbBinderInfo (AfbBinderHandleT *binder, const char*key);
const char* AfbAddOneEvent (afb_api_t apiv4, const char*uid, const char*pattern, afb_event_handler_x4_t callback, void *context);
const char* AfbDelOneEvent(afb_api_t apiv4, const char*pattern, void **context);