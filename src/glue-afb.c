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

#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

#include <libafb/afb-core.h>
#include <libafb/afb-misc.h>
#include <libafb/sys/verbose.h>
#include <libafb/afb-extend.h>
#include <libafb/afb-http.h>
#include <libafb/apis/afb-api-so.h>
#include <libafb/apis/afb-api-ws.h>
#include <libafb/apis/afb-api-rpc.h>

// TBD Jose mission prototype
void afb_api_v4_logmask_set(struct afb_api_v4 *apiv4, int mask);
void set_logmask(int lvl);

#include <uthash.h>
#include <wrap-json.h>
#include <linux/limits.h>

#include "glue-afb.h"
#include "glue-utils.h"

#define AFB_HSRV_OK 1
#define DEFAULT_API_TIMEOUT 180
#define DEFAULT_SESSION_TIMEOUT	32000000
#define DEFAULT_CACHE_TIMEOUT 100000
#define DEFAULT_MAX_SESSION_COUNT 200
#define DEFAULT_HTTP_PORT 1234
#define DEFAULT_BINDER_INTERFACE "*"
#define DEFAULT_JOBS_MAX 200
#define DEFAULT_JOBS_MIN 10
#define DEFAULT_THREADS_POOL 2
#define DEFAULT_THREADS_MAX 5

// make our live simpler
typedef struct afb_hsrv afb_hsrv;
typedef struct afb_hreq afb_hreq;
typedef struct afb_session afb_session;
typedef struct afb_apiset afb_apiset;
typedef struct afb_apiset afb_apiset;
typedef struct afb_verb_v4 afb_verb_v4;
typedef struct afb_api_v4 afb_api_v4;
typedef struct afb_req_v4 afb_req_v4;
typedef struct afb_data afb_data;
typedef struct afb_auth afb_auth;

typedef struct {
    const char *uid;
    afb_auth *perm;
    UT_hash_handle hh;
} afbAclsIndexT;

typedef struct {
    afbAclsIndexT *hTable;
    afb_auth *perms;
} afbAclsHandleT;

typedef struct {
    const char *uid;
    const char *info;
    const int timeout;
    int verbose;
    const int noconcurency;

    const char* supervision;
    const char* rootdir;
    json_object* extendJ;
    json_object* ldpathJ;

    int poolThreadMax;
    const int poolThreadSize;
    const int maxJobs;
    const int minJobs;

    struct {
        const char* rqt;
        const char* evt;
        const char* api;
        const char* glob;
        const char* ses;
    } trace;

    struct {
        const int port;
        const char* basedir;
        const char* rootapi;
        const char* onepage;
        const char* updir;
        const char* cert;
        const char* key;
        json_object* aliasJ;
        json_object* intfJ;
        struct {
            const int session;
            const int cache;
            const int request;
        } timeout;
    } httpd;
    afbAclsHandleT *acls;
} AfbBinderConfigT;

struct AfbBinderHandleS {
    afb_hsrv *hsrv;
    afb_apiset *publicApis;
    afb_apiset *privateApis;
    afb_apiset *restrictedApis;
    afb_api_t  apiv4;
    AfbBinderConfigT *config;
};

static AfbBinderConfigT binderConfigDflt = {
    .uid= "lua-binder",
    .timeout= DEFAULT_API_TIMEOUT,
    .rootdir=".",

    .poolThreadMax=DEFAULT_THREADS_MAX,
    .poolThreadSize=DEFAULT_THREADS_POOL,
    .maxJobs= DEFAULT_JOBS_MAX,
    .minJobs= DEFAULT_JOBS_MIN,

    .httpd.port=DEFAULT_HTTP_PORT,
    .httpd.timeout.session=DEFAULT_SESSION_TIMEOUT,
    .httpd.timeout.cache=DEFAULT_CACHE_TIMEOUT,
    .httpd.basedir=".",
    .httpd.rootapi="/api",
    .httpd.updir="/tmp",
    .httpd.onepage="/opa",
};

typedef enum {
    AFB_EXPORT_PRIVATE=0,
    AFB_EXPORT_RESTRICTED,
    AFB_EXPORT_PUBLIC,
} LuaApiExportE;

const nsKeyEnumT afbApiExportKeys[]= {
    {"private", AFB_EXPORT_PRIVATE},
    {"restricted", AFB_EXPORT_RESTRICTED},
    {"public", AFB_EXPORT_PUBLIC},

    {NULL, -1} // terminator/on-error
};

typedef struct {
    int verbose;
    const char *uid;
    const char *api;
    const char *info;
    LuaApiExportE export;
    const int noconcurency;
    const char *provide;
    const char *require;
    json_object *verbsJ;
    json_object *eventsJ;
    json_object *aliasJ;
    const int seal;
    const char*uri;
    const int lazy;
} AfbApiConfigT;

AfbApiConfigT apiConfigDflt= {
    .verbose=0,
    .seal=1,
};

typedef enum {
    BINDER_INFO_UID,
    BINDER_INFO_INFO,
    BINDER_INFO_PORT,
    BINDER_INFO_HTTPS,
    BINDER_INFO_ROOTDIR,
    BINDER_INFO_HTTPDIR,
} AfbBinderInfoE;

const nsKeyEnumT afbBinderInfoKeys[]={
    {"uid" , BINDER_INFO_UID},
    {"info", BINDER_INFO_INFO},
    {"port", BINDER_INFO_PORT},
    {"https", BINDER_INFO_HTTPS},
    {"httpdir", BINDER_INFO_HTTPDIR},
    {"rootdir", BINDER_INFO_ROOTDIR},

    {NULL, -1} // terminator/on-error
};

const nsKeyEnumT authTypeKeys[]= {
    {"lock" , afb_auth_No},
    {"and"  , afb_auth_And},
    {"or"   , afb_auth_Or},
    {"loa"  , afb_auth_LOA},
    {"not"  , afb_auth_Not},
    {"key" , afb_auth_Permission},

    {NULL, -1} // terminator/on-error
};

static const char* AfbParseOneAcl (afbAclsHandleT *acls, int idx, json_object *permJ) {

    if (!json_object_is_type(permJ, json_type_array)) goto OnErrorExit;

    // allocate permission uid and add it to acls hashtable
    afbAclsIndexT *auth= calloc(1, sizeof(afbAclsIndexT));
    auth->uid= json_object_get_string(json_object_array_get_idx (permJ, 0));
    HASH_ADD_KEYPTR (hh, acls->hTable, auth->uid, strlen(auth->uid), auth);
    auth->perm=&acls->perms[idx];

    // extract permission type
    const char* type= json_object_get_string(json_object_array_get_idx (permJ, 1));
    enum afb_auth_type typePerm= utilLabel2Value(authTypeKeys, type);
    acls->perms[idx].type= typePerm;

    switch (typePerm) {
        afbAclsIndexT *first, *second;
        json_object *firstJ, *secondJ, *loaJ, *valueJ;

        case afb_auth_Permission:
        case afb_auth_No:
        case afb_auth_Not:
            valueJ= json_object_array_get_idx (permJ, 2);
            acls->perms[idx].text= json_object_get_string(valueJ);;
            break;

        case afb_auth_LOA:
            loaJ= json_object_array_get_idx (permJ, 2);
            acls->perms[idx].loa = atoi (json_object_get_string(loaJ));
            break;

        case afb_auth_And:
        case afb_auth_Or:
            valueJ=  json_object_array_get_idx (permJ, 2);
            if (!json_object_is_type(valueJ, json_type_array) || json_object_array_length(valueJ) !=2) goto OnErrorExit;
            firstJ = json_object_array_get_idx (valueJ, 0);
            secondJ= json_object_array_get_idx (valueJ, 1);
            HASH_FIND_STR(acls->hTable, json_object_get_string(firstJ), first);
            if (!first) goto OnErrorExit;

            HASH_FIND_STR(acls->hTable, json_object_get_string(secondJ), second);
            if (!second) goto OnErrorExit;

            acls->perms[idx].first= first->perm;
            acls->perms[idx].first= second->perm;
            break;

        default:
            goto OnErrorExit;
    };

    json_object_get (permJ);
    return NULL;

OnErrorExit:
    return json_object_get_string(permJ);
}

static afbAclsHandleT* AfbParseAcls (json_object *configJ) {
    const char *errorMsg;
    size_t count;

    if (! json_object_is_type (configJ, json_type_array)) goto OnErrorExit;

    count= json_object_array_length (configJ);
    afbAclsHandleT *acls= calloc (1, sizeof(afbAclsHandleT));
    acls->perms= calloc (count+1, sizeof(afb_auth));

    for (int idx=0; idx <count; idx++) {
        json_object *permJ= json_object_array_get_idx (configJ, idx);
        errorMsg= AfbParseOneAcl (acls, idx, permJ);
        if (errorMsg) goto OnErrorExit;
    }

    // do not delete configJ
    json_object_get (configJ);
    return (acls);

OnErrorExit:
    ERROR ("AfbParseAcls:fail acl=%s", errorMsg);
    free(acls->perms);
    free (acls);
    return NULL;
}

// search one acl within API permission hashtable
static const afb_auth* AfbFindOneAcl (afbAclsHandleT *afbAcls, const char *key) {
   afbAclsIndexT *acl;

   if (!afbAcls) goto OnErrorExit;

   HASH_FIND_STR(afbAcls->hTable, key, acl);

   if (!acl) goto OnErrorExit;

   return acl->perm;

OnErrorExit:
    return NULL;
}

static int BinderAddOneAlias (json_object *aliasJ, void *context) {
	AfbBinderHandleT *binder = (AfbBinderHandleT*)context;
    const char *fullpath, *alias= json_object_get_string(aliasJ);
    char prefix[256];
    int status, index;

    // split alias string
    for (index=0; alias[index]; index++) {
        if (alias[index] == ':') break;
        if (index == sizeof(prefix)-1) break;
        prefix[index] = alias[index];
    }
    prefix[index]='\0';
    fullpath= &alias[index+1];

    if (alias[index] != ':') {
		ERROR("BinderAddOneAlias Missing ':' or too long [%s] ignored.", alias);
		goto OnErrorExit;
	}

    status= afb_hsrv_add_alias(binder->hsrv, strdup(prefix), afb_common_rootdir_get_fd(), fullpath, 0, 0);
    if (status != AFB_HSRV_OK) {
		ERROR("BinderAddOneAlias fail to add alias=[%s] path=[%s]", prefix, fullpath);
        goto OnErrorExit;
    }
    DEBUG ("BinderAddOneAlias alias=[%s] path=[%s]", prefix, fullpath);
    return 0;

OnErrorExit:
    return -1;
}

const char* AfbAddOneVerb (AfbBinderHandleT *binder, afb_api_t apiv4, json_object *configJ, afb_req_callback_x4_t callback, void *vcbData) {
    char *errorMsg=NULL;;
    const char *uid=NULL, *verb=NULL, *info=NULL, *auth=NULL;
    const uint32_t session=0;
    int err, regex=0;
    const afb_auth *acl=NULL;

    err= wrap_json_unpack (configJ, "{s?s s?s s?s s?s s?i s?b}"
        , "uid"     , &uid
        , "verb"    , &verb
        , "info"    , &info
        , "auth"    , &auth
        , "session" , &session
        , "regex"   , &regex
        );

    if (err || (!verb && !uid)) {
        errorMsg= (char*)json_object_get_string(configJ);
        goto OnErrorExit;
    }

    // info verb require 'uid' but syntax allows to defined only one of uid|verb
    if (!verb && uid)  verb=uid;
    if (verb &&  !uid) json_object_object_add(configJ, "uid", json_object_new_string(verb));

    if (auth) {
        acl= AfbFindOneAcl (binder->config->acls, auth);
        if (!acl) {
            ERROR ("AfbAddOneVerb: fail finding ACL=%s", auth);
            errorMsg = "AfbAddOneVerb 'auth/acl' undefined";
            goto OnErrorExit;
        }
    }

    err= afb_api_v4_add_verb_hookable (apiv4, verb, info, callback, vcbData, acl, session, regex);
    if (err) {
        errorMsg= (char*)json_object_get_string(configJ);
        goto OnErrorExit;
    }

    json_object_get (configJ);
    return NULL;

OnErrorExit:
    return errorMsg;
}

const char* AfbAddOneEvent (afb_api_t apiv4, const char*uid, const char*pattern, afb_event_handler_x4_t callback, void *context) {
    char *errorMsg=NULL;;
    int err;

    err= afb_api_v4_event_handler_add_hookable (apiv4, pattern, callback, context);
    if (err) {
        errorMsg= "(hoops) afb_api_v4_event_handler_add_hookable fail";
        goto OnErrorExit;
    }

    return NULL;

OnErrorExit:
    return errorMsg;
}

const char* AfbDelOneEvent(afb_api_t apiv4, const char*pattern, void **context) {
    char *errorMsg=NULL;;
    int err;

    err= afb_api_v4_event_handler_del_hookable(apiv4, pattern, context);
    if (err) {
        errorMsg= "(hoops) afb_api_v4_event_handler_del_hookable fail";
        goto OnErrorExit;
    }

    return NULL;

OnErrorExit:
    return errorMsg;
}

const char* AfbAddEvents (afb_api_t apiv4, json_object *configJ, afb_event_handler_x4_t callback) {
    const char *errorMsg, *uid, *pattern;
    AfbVcbDataT *vcbData;
    int err;

    if (json_object_is_type(configJ, json_type_array)) {
        for (int idx=0; idx < json_object_array_length(configJ); idx++) {
            json_object *eventJ= json_object_array_get_idx (configJ, idx);
            pattern=NULL;
            err= wrap_json_unpack (eventJ, "{ss s?s}"
                , "uid", &uid
                , "pattern", &pattern
            );
            if (err) {
                errorMsg=json_object_get_string(eventJ);
                goto OnErrorExit;
            }

            vcbData= calloc (1, sizeof(AfbVcbDataT));
            vcbData->magic= (void*)AfbAddVerbs;
            vcbData->configJ= eventJ;
            vcbData->uid= uid;
            json_object_get(vcbData->configJ);
            errorMsg= AfbAddOneEvent (apiv4, uid, pattern, callback, vcbData);
            if (errorMsg) goto OnErrorExit;
        }

    } else {
        err= wrap_json_unpack (configJ,  "{ss s?s}"
            , "uid", &uid
            , "pattern", &pattern
        );
        if (err) {
            errorMsg=json_object_get_string(configJ);
            goto OnErrorExit;
        }
        vcbData= calloc (1, sizeof(AfbVcbDataT));
        vcbData->configJ= configJ; 
        json_object_get(vcbData->configJ);
        vcbData->magic= (void*)AfbAddVerbs;
        vcbData->uid=uid;
        errorMsg= AfbAddOneEvent (apiv4, uid, pattern, callback, configJ);
        if (errorMsg) goto OnErrorExit;
    }

    return NULL;

OnErrorExit:
    return errorMsg;
}

const char* AfbAddVerbs (AfbBinderHandleT *binder, afb_api_t apiv4, json_object *configJ, afb_req_callback_x4_t callback) {
    const char *errorMsg;
    AfbVcbDataT *vcbData;

    if (json_object_is_type(configJ, json_type_array)) {
        for (int idx=0; idx < json_object_array_length(configJ); idx++) {
            json_object *verbJ= json_object_array_get_idx (configJ, idx);
            vcbData= calloc (1, sizeof(AfbVcbDataT));
            vcbData->magic= (void*)AfbAddVerbs;
            vcbData->configJ= verbJ;
            json_object_get(vcbData->configJ);
            vcbData->uid= json_object_get_string (json_object_object_get(verbJ, "uid"));
            errorMsg= AfbAddOneVerb (binder, apiv4, verbJ, callback, vcbData);
            if (errorMsg) goto OnErrorExit;
        }

    } else {
        vcbData= calloc (1, sizeof(AfbVcbDataT));
        vcbData->configJ= configJ; 
        json_object_get(vcbData->configJ);
        vcbData->magic= (void*)AfbAddVerbs;
        vcbData->uid= json_object_get_string (json_object_object_get(configJ, "uid"));
        errorMsg= AfbAddOneVerb (binder, apiv4, configJ, callback, vcbData);
        if (errorMsg) goto OnErrorExit;
    }

    return NULL;

OnErrorExit:
    return errorMsg;
}

static int AfbApiConfig (json_object *configJ, AfbApiConfigT *config) {
    int err;
    const char*export=NULL;

    // allocate config and set defaults
    memcpy (config, &apiConfigDflt, sizeof(AfbApiConfigT));

    err= wrap_json_unpack (configJ, "{ss s?s s?s s?i s?s s?b s?o s?s s?s s?b s?o s?o s?s}"
        , "uid"    , &config->uid
        , "api"    , &config->api
        , "info"   , &config->info
        , "verbose", &config->verbose
        , "export" , &export
        , "noconcurrency", &config->noconcurency
        , "verbs"  , &config->verbsJ
        , "require", &config->require
        , "uri"    , &config->uri
        , "lazy"   , &config->lazy
        , "alias"  , &config->aliasJ
        , "events" , &config->eventsJ
        , "provide", &config->provide
        );
    if (err) goto OnErrorExit;

    // if api not defined use api
    if (!config->api)  config->api= config->uid;

    if (export) {
        config->export= utilLabel2Value(afbApiExportKeys, export);
        if (config->export < 0) goto OnErrorExit;
    }

    if (config->verbose) config->verbose= verbosity_to_mask(config->verbose);

    // if restricted provide a default URI
    if (config->export == AFB_EXPORT_RESTRICTED && !config->uri) {
        char uri[256];
        snprintf (uri, sizeof(uri), "unix:@%s", config->uid);
        config->uri= strdup (uri);
    }

    json_object_get(configJ);
    return 0;

OnErrorExit:
    return -1;
}

typedef struct {
    AfbBinderHandleT *binder;
    AfbApiConfigT *config;
    json_object *verbs;
    afb_api_callback_x4_t usrApiCb;
    afb_req_callback_x4_t usrInfoCb;
    afb_req_callback_x4_t usrRqtCb;
    afb_event_handler_x4_t usrEvtCb;
    struct afb_apiset* apiDeclSet;
    struct afb_apiset* apiCallSet;
    void *userData;
    const char* errorMsg;
} AfbApiInitT;

static int AfbApiPreInit (afb_api_v4 *apiv4, void *context) {
    AfbApiInitT *init= (AfbApiInitT*) context;
    struct afb_binding_v4 apiDesc;
    int status;

    // set log level
    afb_api_v4_logmask_set (apiv4, init->config->verbose);

    // set api flag
    memset (&apiDesc, 0, sizeof(struct afb_binding_v4));
    apiDesc.provide_class= init->config->provide;
    apiDesc.require_api= init->config->require;
    apiDesc.userdata= init->userData;
    status= afb_api_v4_set_binding_fields(apiv4, &apiDesc, init->usrApiCb);

    if (init->usrInfoCb) {
        json_object *infoJ;
        wrap_json_pack (&infoJ, "{ss ss}"
            ,"verb", "info"
            ,"info", "AfbGlue implicit api introspection api verb"
        );

        init->errorMsg= AfbAddOneVerb (init->binder, apiv4, infoJ, init->usrInfoCb, apiDesc.userdata);
        if (init->errorMsg) goto OnErrorExit;
    }

    if (init->config->eventsJ) {
        init->errorMsg= AfbAddEvents (apiv4, init->config->eventsJ, init->usrEvtCb);
        if (init->errorMsg) goto OnErrorExit;
    }

    if (init->config->verbsJ) {
        init->errorMsg= AfbAddVerbs (init->binder, apiv4, init->config->verbsJ, init->usrRqtCb);
        if (init->errorMsg) goto OnErrorExit;
    }

    if (init->config->seal) afb_api_v4_seal_hookable (apiv4);

    // call preinit now
    status= afb_api_v4_safe_ctlproc (apiv4, init->usrApiCb,afb_ctlid_Pre_Init, (afb_ctlarg_t)NULL);
    return status;

OnErrorExit:
    return -1;
}

const char* AfbApiCreate (AfbBinderHandleT *binder, json_object *configJ, afb_api_t *apiv4, afb_api_callback_x4_t usrApiCb, afb_req_callback_x4_t usrInfoCb, afb_req_callback_x4_t usrRqtCb, afb_event_handler_x4_t usrEvtCb, void *userData) {
    int err, status;
    const char *errorMsg=NULL;;

    AfbApiConfigT config;
    err= AfbApiConfig(configJ, &config);
    if (err) {
        errorMsg=json_object_get_string(configJ);
        goto OnErrorExit;
    }

    // prepare context for preinit function
    AfbApiInitT apiInit;
    apiInit.binder= binder;
    apiInit.config= &config;
    apiInit.usrApiCb= usrApiCb;
    apiInit.usrInfoCb=usrInfoCb;
    apiInit.usrEvtCb= usrEvtCb;
    apiInit.usrRqtCb= usrRqtCb;
    apiInit.userData= userData;

    apiInit.apiCallSet   = binder->privateApis;
    switch (config.export) {
        case AFB_EXPORT_PUBLIC:
            apiInit.apiDeclSet= binder->publicApis;
            break;

        case AFB_EXPORT_RESTRICTED:
            apiInit.apiDeclSet= binder->restrictedApis;
            break;

        case AFB_EXPORT_PRIVATE:
            apiInit.apiDeclSet= binder->privateApis;
            break;

        default:
            errorMsg="invalid api export value";
            goto OnErrorExit;
    }

    // register API
    status = afb_api_v4_create (apiv4, apiInit.apiDeclSet, apiInit.apiCallSet,
                                    config.api, Afb_String_Const,
                                    config.info, Afb_String_Const,
                                    config.noconcurency,
                                    AfbApiPreInit, &apiInit, // pre-ctrlcb + ctx pre-init
                                    NULL, Afb_String_Const  // no binding.so path
    );
    if (status) {
        errorMsg= apiInit.errorMsg;
        goto OnErrorExit;
    }

    // if URI provided and api export allow then export it now
    if (config.uri && config.export != AFB_EXPORT_PRIVATE) {
        err= afb_api_ws_add_server(config.uri, binder->restrictedApis, binder->restrictedApis);
        if (err) {
            errorMsg= "Fail to parse afbApi json config";
            goto OnErrorExit;
        }
    }

    if (config.aliasJ) {
        if (utilScanJson (config.aliasJ, BinderAddOneAlias, binder) < 0) {
            errorMsg= "afb_api registering aliases fail";
            goto OnErrorExit;
        }
    }

    json_object_get (configJ);
    return NULL;

OnErrorExit:
    *apiv4=NULL;
    return errorMsg;
}

// import API client from uri and map corresponding roles into apis hashtable
const char* AfbApiImport (AfbBinderHandleT *binder, json_object *configJ) {
    int err, index;
    char *errorMsg=NULL;;
    afb_apiset *apiset;

    AfbApiConfigT config;
    err= AfbApiConfig(configJ, &config);
    if (err) {
        errorMsg="Fail to parse API";
        goto OnErrorExit;
    }

    switch (config.export) {
        case AFB_EXPORT_PUBLIC:
            apiset= binder->publicApis;
            break;

        case AFB_EXPORT_RESTRICTED:
            apiset= binder->restrictedApis;
            break;

        case AFB_EXPORT_PRIVATE:
        default:
            apiset=binder->privateApis;
            break;
    }

    err = afb_api_ws_add_client (config.uri, apiset , binder->privateApis, !config.lazy);
    if (err) {
        errorMsg="Invalid imported api URI";
        goto OnErrorExit;
    }

    // Extract API from URI
    for (index = (int)strlen(config.uri)-1; index > 0; index--) {
        if (config.uri[index] == '@' || config.uri[index] == '/') break;
    }

    // If needed create an alias
    if (index) {
        if (strcasecmp (&config.uri[index + 1], config.uid)) {
            err = afb_apiset_add_alias (binder->privateApis, &config.uri[index + 1], config.uid);
            if (err) {
                errorMsg= "AfbApiImport: api not found";
                goto OnErrorExit;
            }
        }
    }

    return NULL;

  OnErrorExit:
    return errorMsg;
}

static AfbBinderConfigT* BinderParseConfig (json_object *configJ) {
    int err;
    json_object *ignoredJ;
    json_object *aclsJ=NULL;

    // allocate config and set defaults
    AfbBinderConfigT *config= calloc (1, sizeof(AfbBinderConfigT));
    memcpy (config, &binderConfigDflt, sizeof(AfbBinderConfigT));

    err= wrap_json_unpack (configJ, "{ss s?s s?i s?i s?b s?i s?s s?s s?s s?s s?s s?o s?o s?o s?o s?o s?i s?i s?o !}"
        , "uid"    , &config->uid
        , "info"   , &config->info
        , "verbose", &config->verbose
        , "timeout", &config->timeout
        , "noconcurrency", config->noconcurency
        , "port", &config->httpd.port
        , "roothttp", &config->httpd.basedir
        , "rootapi", &config->httpd.rootapi
        , "rootdir", &config->rootdir
        , "https-cert", &config->httpd.cert
        , "https-key" , &config->httpd.key
        , "alias", &config->httpd.aliasJ
        , "intf", &config->httpd.intfJ
        , "extentions", &config->extendJ
        , "ldpath", &config->ldpathJ
        , "acls", &aclsJ
        , "thread-pool", &config->poolThreadSize
        , "thread-max" , &config->poolThreadMax
        , "onerror", &ignoredJ
        );
    if (err) goto OnErrorExit;

    // move from level to mask
    if (config->verbose) config->verbose= verbosity_to_mask(config->verbose);

    if (aclsJ) {
        config->acls= AfbParseAcls (aclsJ);
        if (!config->acls) goto OnErrorExit;
    }

    json_object_get(configJ);
    return (config);

OnErrorExit:
    free (config);
    return NULL;
}

char* AfbBinderHttpd(AfbBinderHandleT *binder) {
    char *errorMsg=NULL;;
    int status;

    // the minimum we need is a listening port
    if (binder->config->httpd.port <= 0) {
        errorMsg= "invalid port";
        goto OnErrorExit;
    }

    // initialize cookie
	if (!afb_hreq_init_cookie(binder->config->httpd.port, 0, binder->config->httpd.timeout.session)) {
		errorMsg= "HTTP cookies init";
		goto OnErrorExit;
	}

    // set upload directory
	if (afb_hreq_init_download_path(binder->config->httpd.updir) < 0) {
		errorMsg= "set upload dir";
		goto OnErrorExit;
	}

	// create afbserver
	binder->hsrv = afb_hsrv_create();
	if (binder->hsrv == NULL) {
		errorMsg= "Allocating afb_hsrv_create";
		goto OnErrorExit;
	}

	// initialize the cache timeout
	if (!afb_hsrv_set_cache_timeout(binder->hsrv, binder->config->httpd.timeout.cache)) {
		errorMsg= "Allocating afb_hsrv_create";
		goto OnErrorExit;
	}

	// set the root api handlers for http websock
	if (!afb_hsrv_add_handler(binder->hsrv, binder->config->httpd.rootapi, afb_hswitch_websocket_switch, binder->publicApis, 20)) {
		errorMsg= "Allocating afb_hswitch_websocket_switch";
		goto OnErrorExit;
    }

    // set root api for http rest
	if (!afb_hsrv_add_handler(binder->hsrv, binder->config->httpd.rootapi, afb_hswitch_apis,binder->publicApis, 10)) {
		errorMsg= "Allocating afb_hswitch_apis";
		goto OnErrorExit;
    }

	// set OnePageApp rootdir
	if (!afb_hsrv_add_handler(binder->hsrv,  binder->config->httpd.onepage, afb_hswitch_one_page_api_redirect, NULL, -20)) {
		errorMsg= "Allocating one_page_api_redirect";
		goto OnErrorExit;
    }

    // loop to register all aliases
    if (utilScanJson (binder->config->httpd.aliasJ, BinderAddOneAlias, binder) < 0) {
		errorMsg= "Registering aliases";
		goto OnErrorExit;
    }

	// set server rootdir path
    status= afb_hsrv_add_alias(binder->hsrv, "", afb_common_rootdir_get_fd(), binder->config->httpd.basedir, -10, 1);
    if (status != AFB_HSRV_OK) {
		errorMsg= "Registering httpd basedir";
		goto OnErrorExit;
    }

	return NULL;

OnErrorExit:
	if (binder->hsrv) afb_hsrv_put(binder->hsrv);
    ERROR("AfbBinderHttpd: fail to start httpd server [%s]", errorMsg);
    return errorMsg;
}

const char* AfbBinderInfo (AfbBinderHandleT *binder, const char*key) {
    const char* value;
    char number[32];
    AfbBinderInfoE rqt= utilLabel2Value (afbBinderInfoKeys, key);
    switch (rqt) {

        case BINDER_INFO_UID:
            value= strdup (binder->config->uid);
            break;

        case BINDER_INFO_PORT:
            snprintf (number, sizeof(number),"%i", binder->config->httpd.port);
            value= strdup (number);
            break;

        case BINDER_INFO_ROOTDIR:
            value= strdup (binder->config->rootdir);
            break;

        case BINDER_INFO_HTTPDIR:
            value= strdup (binder->config->httpd.basedir);
            break;

        default: goto OnErrorExit;
    }

    return value;

OnErrorExit:
    return NULL;
}

// search for file within dirnameJ returns an open file decriptor on file when exist
static int AfbScanLdPathCb (json_object *dirnameJ, void *context) {
    char* basename= (char*)context;
    const char* dirname= json_object_get_string(dirnameJ);
    int dirFd, fileFd;

    dirFd= open(dirname, O_RDONLY);
    if (dirFd <= 0) goto OnErrorExit;

    fileFd= openat (dirFd, basename, O_RDONLY);
    close (dirFd);
    if (fileFd < 0) goto OnErrorExit;

    return fileFd;

OnErrorExit:
    ERROR ("AfbScanLdPathCb: not-found/ignored dirname=%s filename=%s", dirname, basename);
    return 0;
}

const char* AfbBindingLoad (AfbBinderHandleT *binder, json_object *bindingJ) {
    const char *errorMsg=NULL, *uri=NULL;
    afb_apiset *apiDeclSet, *apiCallSet;
    int err, fileFd=0;
    const char *uid, *libpath, *export=NULL;
    json_object *aliasJ=NULL, *ldpathJ=NULL, *configJ=NULL;
    int public=0;

    err= wrap_json_unpack (bindingJ, "{ss ss s?s s?o s?o s?o}"
        ,"uid"    , &uid
        ,"path"   , &libpath
        ,"export" , &export
        ,"uri"    , &uri
        ,"ldpath" , &ldpathJ
        ,"alias"  , &aliasJ
    );
    if (err) {
        errorMsg= "fail parsing json binding config";
        goto OnErrorExit;
    }

    int exportMod= utilLabel2Value(afbApiExportKeys, export);
    apiCallSet= binder->privateApis;
    switch (exportMod) {
        case AFB_EXPORT_PUBLIC:
            apiDeclSet= binder->publicApis;
            break;

        case AFB_EXPORT_RESTRICTED:
            apiDeclSet= binder->restrictedApis;
            if (!uri) {
                char buffer[256];
                snprintf (buffer, sizeof(buffer), "unix:@%s", uid);
                uri=strdup(buffer);
            }
            break;

        case AFB_EXPORT_PRIVATE:
            apiDeclSet= binder->privateApis;
            break;

        default:
            errorMsg="invalid api export value";
            goto OnErrorExit;
    }

    if (aliasJ) {
        if (utilScanJson (aliasJ, BinderAddOneAlias, binder) < 0) {
		    errorMsg= "afb_api registering aliases fail";
		    goto OnErrorExit;
        }
    }

    // api public/private visibility
    if (public) apiDeclSet= binder->publicApis;
    else apiDeclSet= binder->privateApis;

    // check if binding exist within binding/binder ldpath
    if (libpath[0] != '/') {
        if (ldpathJ) fileFd= utilScanJson (ldpathJ, AfbScanLdPathCb, (void*)libpath);
        if (fileFd <=0 && binder->config->ldpathJ) fileFd= utilScanJson (binder->config->ldpathJ, AfbScanLdPathCb, (void*)libpath);
    }

    if (fileFd <= 0) {
        // let's try binding load with LD_LIBRAY_PATH
        err= afb_api_so_add_binding_config(libpath, apiDeclSet, apiCallSet, configJ);
    } else {
        // if binding exist let get fullpath
        char fullpath[PATH_MAX];
        err= utilFdToPath (fileFd, fullpath, sizeof(fullpath));
        close (fileFd);
        if (err) {
   		    errorMsg= "(hoops) binding fullpath too long";
            goto OnErrorExit;
        }
        err= afb_api_so_add_binding_config(fullpath, apiDeclSet, apiCallSet, configJ);
    }
    if (err) {
        errorMsg= "afb_api binding load fail";
        goto OnErrorExit;
    }

    if (uri && exportMod != AFB_EXPORT_PRIVATE) {
        err= afb_api_ws_add_server(uri, apiDeclSet, apiDeclSet);
        if (err) goto OnErrorExit;
    }

    return NULL;

OnErrorExit:
    ERROR ("AfbBindingLoad:fatal [uid=%s] %s", uid, errorMsg);
    return errorMsg;
}

afb_api_t AfbBinderGetApi (AfbBinderHandleT *binder) {
    return binder->apiv4;
}

// binder API control callback
static int AfbBinderCtrlCb(afb_api_t apiv4, afb_ctlid_t ctlid, afb_ctlarg_t ctlarg, void *context) {
    static int count=0;
    switch (ctlid) {
        case afb_ctlid_Orphan_Event:
            afb_api_v4_verbose (apiv4, AFB_SYSLOG_LEVEL_INFO, __file__,__LINE__,__func__, "orphan event=[%s] count=[%d]", ctlarg->orphan_event.name, count++);
            break;
        //case afb_ctlid_Root_Entry:
        //case afb_ctlid_Pre_Init:
        //case afb_ctlid_Init:
        //case afb_ctlid_Class_Ready:
        //case afb_ctlid_Exiting:
        default:
            break;
    }
    return 0;
}

const char* AfbBinderConfig (json_object *configJ, AfbBinderHandleT **handle, void *userdata) {
    const char *errorMsg=NULL;;
    AfbBinderConfigT* config=NULL;
    AfbBinderHandleT *binder=NULL;
    int status;
    unsigned traceFlags;

    config= BinderParseConfig (configJ);
	if (!config) {
        errorMsg= "fail to parse binding config";
        goto OnErrorExit;
    }
    json_object_get(configJ);

    // create binder handle and select default config
    binder= calloc (1, sizeof(AfbBinderHandleT));
    binder->config=config;

    // set binder global verbosity
    set_logmask(verbosity_to_mask(config->verbose));

	// create private and public ApiSet
	binder->privateApis = afb_apiset_create("private", config->timeout);
	if (!binder->privateApis) {
		errorMsg= "can't create main apiset";
		goto OnErrorExit;
	}
	binder->restrictedApis = afb_apiset_create_subset_first(binder->privateApis, "restricted", config->timeout);
	if (!binder->restrictedApis) {
		errorMsg= "can't create restricted apiset";
		goto OnErrorExit;
	}
	binder->publicApis = afb_apiset_create_subset_first(binder->restrictedApis, "public", config->timeout);
	if (!binder->publicApis) {
		errorMsg= "can't create public apiset";
		goto OnErrorExit;
	}

    // create private global api to handle events
    status = afb_api_v4_create (&binder->apiv4, binder->privateApis, binder->privateApis,
                                    config->uid, Afb_String_Const,
                                    NULL, Afb_String_Const,
                                    1, // no concurency
                                    NULL, NULL, // pre-ctrlcb + ctx pre-init
                                    NULL, Afb_String_Const  // no binding.so path
    );
    if (status) {
        errorMsg= "failed to create internal private binder API";
        goto OnErrorExit;
    }

    // add userdata to main binder api
    if (userdata) afb_api_set_userdata(binder->apiv4, userdata);

    afb_api_v4_set_mainctl(binder->apiv4, AfbBinderCtrlCb);

	afb_global_api_init(binder->privateApis);
	status = afb_monitor_init(binder->publicApis, binder->restrictedApis);
	if (status < 0) {
		errorMsg= "failed to setup monitor";
		goto OnErrorExit;
	}

    if (config->supervision) {
    	status = afb_supervision_init(binder->privateApis, configJ);
        if (status < 0) {
            errorMsg= "failed to setup supervision";
            goto OnErrorExit;
        }
    }

	if (config->trace.rqt) {
		status = afb_hook_flags_req_from_text(config->trace.rqt, &traceFlags);
		if (status < 0) {
			errorMsg= "invalid tracereq";
			goto OnErrorExit;
		}
		afb_hook_create_req(NULL, NULL, NULL, traceFlags, NULL, NULL);
	}
	if (config->trace.api) {
		status = afb_hook_flags_api_from_text(config->trace.api, &traceFlags);
		if (status < 0) {
			errorMsg= "invalid traceapi";
			goto OnErrorExit;
		}
		afb_hook_create_api(NULL, traceFlags, NULL, NULL);
	}
	if (config->trace.evt) {
		status = afb_hook_flags_evt_from_text(config->trace.evt, &traceFlags);
		if (status < 0) {
			errorMsg= "invalid traceevt";
			goto OnErrorExit;
		}
		afb_hook_create_evt(NULL, traceFlags, NULL, NULL);
	}
	if (config->trace.ses) {
		status = afb_hook_flags_session_from_text(config->trace.ses, &traceFlags);
		if (status < 0) {
			errorMsg= "invalid traceses";
			goto OnErrorExit;
		}
		afb_hook_create_session(NULL, traceFlags, NULL, NULL);
	}
	if (config->trace.glob) {
		status = afb_hook_flags_global_from_text(config->trace.glob, &traceFlags);
		if (status < 0) {
			errorMsg= "invalid traceglob";
			goto OnErrorExit;
		}
		afb_hook_create_global(traceFlags, NULL, NULL);
	}

    if (config->extendJ) {
        status = afb_extend_config(config->extendJ);
        if (status < 0) {
            errorMsg= "Extension config failed";
            goto OnErrorExit;
        }
    }

    if (afb_common_rootdir_set(config->rootdir) < 0) {
		errorMsg= "Rootdir set fail";
		goto OnErrorExit;
	}

    if (config->httpd.port) {
        errorMsg = AfbBinderHttpd(binder);
        if (errorMsg) goto OnErrorExit;
    }

    *handle= binder;
    return NULL;

OnErrorExit:
    ERROR ("luaBinderConfig:fatal %s", errorMsg);
    if (binder) free (binder);
    if (config) free (config);
    *handle=NULL;
    return errorMsg;
}

static int BinderAddIntf(json_object *intfJ, void* context) {
    AfbBinderHandleT *binder = (AfbBinderHandleT*)context;
    int status;
    char buffer[512];
    const char* intf;

    if (!intfJ) {
        int count;
        intf = buffer;
   		count = snprintf(buffer, sizeof(buffer), "tcp:%s:%d", DEFAULT_BINDER_INTERFACE, binder->config->httpd.port);
        if (count == sizeof(buffer)) goto OnErrorExit;
        status = afb_hsrv_add_interface(binder->hsrv, intf);
    } else {
        intf = json_object_get_string (intfJ);
        status= afb_hsrv_add_interface(binder->hsrv, intf);
    }
    if (status < 0) goto OnErrorExit;
	return 0;

OnErrorExit:
    ERROR ("BinderAddIntf: fail adding interface=%s", intf);
    return -1;
}

typedef struct {
    AfbBinderHandleT *binder;
    AfbStartupCb callback;
    void *config;
    void *context;
} AfbBinderInitT;


void BinderStartCb (int signum, void *context) {
    const char *errorMsg=NULL;;
    AfbBinderInitT *init = (AfbBinderInitT*)context;
    AfbBinderHandleT *binder= init->binder;
    int status=0;

    // resolve dependencies and start binding services
    status= afb_apiset_start_all_services (binder->privateApis);
    if (status) {
        errorMsg= "Fail to start all services";
        goto OnErrorExit;
    }

    if (binder->config->httpd.port) {
        status= !afb_hsrv_start_tls(binder->hsrv, 15, binder->config->httpd.cert, binder->config->httpd.key);
        if (status) {
            errorMsg= "Fail to start httpd service";
            goto OnErrorExit;
        }
    }

    // start interface
    if (binder->config->httpd.intfJ) utilScanJson (binder->config->httpd.intfJ, BinderAddIntf, binder);
    else {
        int err= BinderAddIntf (NULL, binder);
        if (err) {
            errorMsg="listen fail";
            goto OnErrorExit;
        }
    }

    // start user startup function
    if (init->callback) {
        status= init->callback (init->config, init->context);
        if (status < 0) {
            errorMsg= "startup abort";
            goto OnErrorExit;
        }
    }
    free(init);

    // if status == 0 keep mainloop running
    if (!status) NOTICE ("Binder [%s] running", binder->config->uid);
    else AfbBinderExit(binder, status);
    return;

OnErrorExit:
    WARNING ("BinderStart: exit message=[%s]", errorMsg);
    errorMsg= "startup abort";
    AfbBinderExit(binder, status);
}

// Force mainloop exit
void AfbBinderExit(AfbBinderHandleT *binder, int exitcode) {
    afb_sched_exit (1, NULL /*callback*/, NULL/*context*/, exitcode);
}

int AfbBinderGetLogMask(AfbBinderHandleT *binder) {
    return logmask;
}

// start binder scheduler within a new thread
int AfbBinderStart (AfbBinderHandleT *binder, void *config, AfbStartupCb callback, void *context) {
    AfbBinderInitT *binderCtx = calloc(1, sizeof(AfbBinderInitT));
    binderCtx->config= config;
    binderCtx->binder= binder;
    binderCtx->context=context;
    binderCtx->callback= callback;

    if (binder->config->poolThreadMax > binder->config->poolThreadSize+1) binder->config->poolThreadMax = binder->config->poolThreadSize+1;
    int status= afb_sched_start(binder->config->poolThreadMax, binder->config->poolThreadSize, binder->config->maxJobs, BinderStartCb, binderCtx);
    return status;
}

// start binder scheduler within current thread context
int AfbBinderEnter (AfbBinderHandleT *binder, void *config, AfbStartupCb callback, void *context) {
    AfbBinderInitT *binderCtx = calloc(1, sizeof(AfbBinderInitT));
    binderCtx->config= config;
    binderCtx->binder= binder;
    binderCtx->context=context;
    binderCtx->callback= callback;

    BinderStartCb(0, binderCtx);
    return 0;
}


// pop afb waiting event and process them
void GluePollRunJobs(void) {
    afb_ev_mgr_wait_and_dispatch(0);
    for (struct afb_job *job= afb_jobs_dequeue(0); job; job= afb_jobs_dequeue(0)) {
        afb_jobs_run(job);
    }
    afb_ev_mgr_prepare();
}