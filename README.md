# libafbglue

AFB glulib provides a hight level abstraction of afb-libafb for integration with non C/C++ languages as Lua, Python, NodeJs, ...
* Author   : Fulup Ar Foll fulup@iot.bzh
* Copyright: 2021 by iot.bzh

## dependencies

* afb-libafb and its dependencies
* uthash
* afb-cmake-modules

## building

```bash
    mkdir build && cd build && cmake .. && make
```

## const char* AfbBinderConfig(json_object *configJ, AfbBinderHandleT **handle);

Build binder configuration from json configJ object. Return a valid binder handle or an error message.

```c
    json_object *configJ;     // should hold a valid json binder config
    AfbBinderHandleT *binder; // binder abstract handle
    const char* errorMsg;
    errorMsg= AfbBinderConfig(configJ, &binder);
    if (errorMsg) goto OnErrorExit;
```

Typical JSON configuration
```json
{
    "uid": "binder-uid",
    "port": 1234, // http port (default no http)
    "verbose": 3, // verbosity level 0-9
    "roothttp": "./conf.d/project/htdocs",
}
```

Full json configuration

```json
{
    ,"uid": "my-binder-uid"
    ,"info": "free text"
    ,"verbose": 0        // 0-9
    ,"timeout": 32000000 // global http timeout
    , "noconcurrency": 0 // prevent API concurency
    , "port": 1234       // http port when 0 no http service starts
    , "roothttp": "."    // default '.'
    , "rootapi": "/api"  // default '/api'
    , "rootdir": "."     // default '.'
    , "https-cert": "/my/ssl/path/httpd.cert"  // ssl certificate path (default no ssl)
    , "https-key": "/my/ssl/path/httpd.key"    // ssl cert key
    , "alias": [{"my-alias:/My-alias/path"}]   // optional list of aliases
    , "intf": "*"        // list of listening interfaces default='*' (all)
    , "extentions":{}    // optional extention configuration
    , "ldpath": ["/opt/helloworld-binding/lib","/usr/local/helloworld-binding/lib"]// binding global search path
    , "acls": {} // optional access control list
    , "thread-pool": 1   // thread pool size. Note than standard operations: verb,event,timer,... do not extend thread pool. When needed they are pushed on waiting queue.
    , "thread-max" : 1   // autoclean thread pool when bigger than max (may temporaly get bigger)   
}
```

## const char* AfbBindingLoad (AfbBinderHandleT *binder, json_object *bindingJ);

Load an existing binding and imports its APIs.

```C
    const char errroMsg;
    json_object *bindingJ; // should hold a valid binding configuration
    errorMsg= AfbBindingLoad (binder, bindingJ);
    if (errorMsg) goto OnErrorExit
```

Typical binding configuration

```json
{
   "uid"    : "helloworld",  // binding uid use debug purpose only
   "export" : "private",     // private, restricted public (see here after note)
   "path"   : "afb-helloworld-skeleton.so", // binding relative or full path
   "ldpath" : ["/opt/helloworld-binding/lib","/usr/local/helloworld-binding/lib"], // binding search path comme before default binder search path
   "alias"  : ["/hello:'/opt/helloworld-binding/htdocs","/devtools:/usr/share/afb-ui-devtools/binder"], // alias list added to global binder existing list
}
```
Note: on "export":
 * public: binding api(s) is visible from HTTP
 * restricted: binding api(s) is exportable only as a unix domain socket
 * private: all binding api(s) are visible for internal subcall and not visible from monitoring


Full configuration

```json
{
    , "uid"    : "my-api-uid"  // used a API name not api not set
    , "api"    : "my-api-name" // default uuid
    , "info"   : "free text"   // no default
    , "verbose": 0             // api verbosity 0-9 (note does not inherit from binder level)
    , "export" : ["private", "restricted", "public"] // see previous note
    , "uri"    : "unix:@my-api" // binding unix socket URI
    , "alias"  : [] // optional list of aliases
    , "ldpath" : [] // binding search path
}
```

## const char* AfbApiImport (AfbBinderHandleT *binder, json_object *configJ);

AFB microservice architecture allows to import external APIs. This mechanism make an external API(s) visible from inside a binder as if it was existing locally.

```C
    const char* errorMsg;
    json_object *configJ; // should hold a valid shadow API config
    errorMsg= AfbApiImport (binder, configJ);
    if (errorMsg) goto OnErrorExit
```

Typical configuration

```json
    , "uid"    : "my-api-uid"  // used a API name not api not set
    , "info"   : "free text"   // no default
    , "verbose": 0             // api verbosity 0-9 (note does not inherit from binder level)
    , "export" : ["private", "restricted", "public"] // see previous note
    , "uri"    : "unix:@my-api" // imported API URI
    , "lazy"   : true|false // prevent or not binder to start when external API is not acting
```

Note on URI: The “@api_name is the preferred method to import API from bindings running on the same Linux instance, to import API from binding running on the remote Linux instance use ‘tcp:hostname:port/api’ as with the –ws-client afb-binding command line option.


## const char* AfbApiCreate   (AfbBinderHandleT *binder, json_object *configJ, afb_api_t *afbApi, afb_api_callback_t usrApiCb, afb_req_callback_x4_t usrInfoCb, afb_req_callback_x4_t usrRqtCb, afb_event_handler_x4_t usrEvtCb, void *userData);

This API allows to create API equivalent as the one created through a binding.

```c

    // optional: called before API is ready (config state) and when api is ready (ready state). [further information](https://docs.redpesk.bzh/docs/en/master/developer-guides/reference-v4/types-and-globals.html#the-type-afb_api_callback_t)
    int ctrlApiCb(afb_api_t apiv4, afb_ctlid_t ctlid, afb_ctlarg_t ctlarg, void *context);

    // optional: should return a valid 'info' api introspection devtools api. [further information](https://docs.redpesk.bzh/docs/en/master/developer-guides/monitoring.html#info-verb-usage)
    void usrInfoCb(afb_req_t afbRqt, unsigned nparams, afb_data_t const params[]);

    // mandatory main API callback. Is called for every verbs defined within API verb section. Note that on 1st call the API as the responsibility to parse JSON verb configuration and store the result in such a way that parsing is not going to happen for further call, through 'json_object_set_userdata' or equivalent model.
    void usrRqtCb(afb_req_t afbRqt, unsigned nparams, afb_data_t const params[]) {
        json_object *configJ = afb_req_get_vcbdata(afbRqt);
    };

    // equivalent to verbs callback but for events
    void usrEvtCb (void *context, const char *evtName, unsigned nparams, afb_data_x4_t const params[], afb_api_t api);

    const char *errorMsg; // receive optional error message
    afb_api_t *afbApi;    // pointer where to store libafb api handle
    void *userData = calloc 1, sizeof(...); // user context is passed to callbacks

    errorMsg= AfbApiCreate(binder, configJ, &afbApi , ctrlApiCb, usrInfoCb, usrRqtCb, usrEvtCb, userData);
    if (errorMsg) goto OnErrorExit;

```

Typical json configuration

```json
"myAapi": {
    "uid"     : "lua-demo",    // api uid
    "api"     : "demo",        // api name
    "info"    : "lua api demo",// free text
    "export"  : "public",      // level of visibility
    "verbose" : 9,             // api verbosity 0-9
    "verbs"   : myVerbs,       // array of verbs config
    "events"  : myEvents,      // optional array of events
    "alias"   : ["/devtools:/usr/share/afb-ui-devtools/binder"], // optional aliases
},

"myVerbs": [
    {"uid":"lua-ping", "verb":"ping", "func":"pingCB"  , "info":"lua ping demo function"},
    {"uid":"lua-args", "verb":"args", "func":"argsCB", "info":"lua check input query", "sample":[{"arg1":"arg-one", "arg2":"arg-two"}, {"argA":1, "argB":2}],
],

"myEvents" : [
    {"uid":"lua-event" , "pattern":"lua-event", "func":"evtTimerCB" , "info":"timer event handler"},
    {"uid":"lua-other" , "pattern":"*", "func":"evtOtherCB" , "info":"any other event handler"},
]

```

Full configuration

```json
    "uid"     : "lua-demo",    // api uid
    "api"     : "demo",        // api name
    "class"   : "test",        // optional api class
    "info"    : "lua api demo",// free text
    "export"  : "public",      // level of visibility
    "seal"    : true,          // lock API after creation
    "verbose" : 9,             // api verbosity 0-9
    "verbs"   : myVerbs,       // array of verbs config
    "events"  : myEvents,      // optional array of events
    "alias"   : ["/devtools:/usr/share/afb-ui-devtools/binder"], // optional aliases
    "noconcurrency": 0, // when set prevent API from using multi-thread
    "require": ["api-1", "api-2"],   // list of API dependency
    "uri"    : "My-Export-Api-Uri",  // when public or restricted API might be exported as unix domain socket
```

## int status= AfbBinderStart (binder, json_object *configJ, startupCb, userdata);

Start previously configured binder services. When ready this API calls 'AfbStartupCb' if this function return 0, the binder enter the mainloop otherwise it exit with corresponding error status.

```c
int startupCb(json_object *configJ, void *userdata);

json_object *configJ; // a json object passed to startup callback
void *userdata; // any abstract pointer pass to the callback
int status= AfbBinderStart (binder, json_object *configJ, startupCb, userdata);

```
Note:
 * They is no default for configJ, that is not parsed by AfbBinderStart.
 * When executing startupCb all binder apis/services are ready, also this callback may use every existing libafb apis.

## void AfbBinderExit(AfbBinderHandleT *binder, int exitcode);

Force binder to exit from the mainloop with corresponding status.

```c
void AfbBinderExit(AfbBinderHandleT *binder, int exitcode);
```

## Misc APIs

### int AfbBinderGetLogMask(AfbBinderHandleT *binder);

return the integer matching binder log level.

### afb_api_t AfbBinderGetApi (AfbBinderHandleT *binder);

return binder internal API. Each binder create a private API matching it UID.

### const char* AfbAddVerbs (AfbBinderHandleT *binder, afb_api_t apiv4, json_object *configJ, afb_req_callback_t callback);

The function is typically called automatically from AfbApiCreate and when call independantly uses the same configuration and callback.

### const char* AfbAddOneVerb (AfbBinderHandleT *binder, afb_api_t apiv4, json_object *configJ, afb_req_callback_t callback, void *vcbData);

When API is not sealed, allow to add new verb with specific callback on existing API. By default verb are added at API pre-init phase from within AfbApiCreate and then it is locked to prevent user from changing it.

### const char* AfbAddEvents (afb_api_t apiv4, json_object *configJ, afb_event_handler_t callback);

Equivalent to AfbAddVerbs but for events.

### const char* AfbBinderInfo (AfbBinderHandleT *binder, const char*key);

Return configuration information about binder

### const char* AfbAddOneEvent (afb_api_t apiv4, json_object *configJ, afb_event_handler_x4_t callback, void *context);

Equivalent to AfbAddOneVerb but for events