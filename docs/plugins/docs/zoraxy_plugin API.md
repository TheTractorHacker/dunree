# Zoraxy Plugin APIs
This API documentation is auto-generated from the Zoraxy plugin source code.


<pre><code class='language-go'>
package zoraxy_plugin // import "{{your_module_package_name_in_go.mod}}/mod/plugins/zoraxy_plugin"


CONSTANTS

const (
	MaxBodyPreviewBytes  = 64 * 1024  // upper bound of HookSettings.BodyPreviewBytes
	DefaultHookTimeoutMs = 2000       // used when HookSettings.TimeoutMs is 0
	MaxHookTimeoutMs     = 10000      // upper bound of HookSettings.TimeoutMs
	MaxDenyBodyBytes     = 64 * 1024  // upper bound of DenyAction.Body
	MaxVerdictBytes      = 256 * 1024 // upper bound of the whole verdict JSON
	MaxHeaderOps         = 32         // header operations per verdict
	MaxHeaderValueBytes  = 8 * 1024   // single header value
	MaxPathBytes         = 4 * 1024   // rewritten path
	MaxQueryBytes        = 8 * 1024   // rewritten query
	InvokeTokenHeader    = "X-Zoraxy-Plugin-Token"
	RequestIDHeader      = "X-Zoraxy-RequestID"
)
    Limits enforced by Zoraxy and the helper functions in this package.

const (
	ActionAllow   = "allow"   // continue
	ActionDeny    = "deny"    // answer the client with Deny
	ActionModify  = "modify"  // apply Modify, then continue
	ActionCapture = "capture" // post_auth only: proxy the whole request to the plugin dynamic capture ingress
)
    Verdict actions

const (
	SDKVersion = "1.2.0"
	APIVersion = 1
)
    SDK and contract version

    SDKVersion is the version of this package (semantic versioning,
    see CHANGELOG.md next to this file). It changes with every release of the
    package.

    APIVersion is the version of the plugin contract this package implements:
    what Zoraxy and a plugin say to each other (introspect, configure,
    calls, events). It only changes when the contract itself changes in
    a way a plugin or Zoraxy has to know about. The written contract is
    docs/plugins/contract.md in the Zoraxy repository. A plugin that declares no
    api_version is a "legacy" plugin (version 0) and keeps working.

const (
	ConfigureViaStdin  = "stdin"            //value of IntroSpect.ConfigureVia
	ConfigureStdinFlag = "-configure-stdin" //flag a plugin is started with when it declared ConfigureViaStdin

)
const HookAPIVersion = 1
    HookAPIVersion is the version of the hooks / filter API described in this
    file.


VARIABLES

var ErrAPIEndpoint = errors.New("zoraxy_plugin: the API endpoint must be a path that starts with \"/\"")
    ErrAPIEndpoint is returned when the endpoint given to an API helper is not a
    path that starts with "/" (an absolute URL is refused, so the key cannot be
    sent elsewhere).

var ErrNoAPIKey = errors.New("zoraxy_plugin: no API key in the start configuration (the manifest needs permitted_api_endpoints)")
    ErrNoAPIKey is returned by the API helpers when Zoraxy handed no API key (or
    no port) to this plugin: the manifest has no PermittedAPIEndpoints.


FUNCTIONS

func HealthHandler(check func() error) http.Handler
    HealthHandler returns a handler for the path you declared as
    IntroSpect.HealthPath.

    It answers 200 "ok" while check returns nil and 503 otherwise (the text of
    the error is not sent). Pass nil when being able to answer is all there is
    to check. Keep check fast: Zoraxy gives a health check 2 seconds.

func NewFilterHandler(invokeToken string, handler FilterHandler) http.Handler
    NewFilterHandler returns an http.Handler for the filter endpoint. It checks
    the invoke token (ConfigureSpec.InvokeToken; pass "" to disable the check),
    decodes the FilterRequest, calls the handler and encodes the verdict.
    Mount it on the path declared as HookSettings.FilterRequestPath /
    FilterResponsePath.

func RequireInvokeToken(token string, next http.Handler) http.Handler
    RequireInvokeToken wraps a handler so that only calls carrying the Zoraxy
    invoke token are served. An empty token disables the check (older Zoraxy
    versions do not send one). Use it for filter and sniff endpoints so other
    local processes cannot call them.

func ServeIntroSpect(pluginSpect *IntroSpect)
    ServeIntroSpect Function

    This function will check if the plugin is initialized with -introspect flag,
    if so, it will print the intro spect and exit

    Place this function at the beginning of your plugin main function

func VerifyInvokeToken(token string, r *http.Request) bool
    VerifyInvokeToken checks the X-Zoraxy-Plugin-Token header in constant time.


TYPES

type ConfigureSpec struct {
	Port         int                  `json:"port"`                   //Port to listen
	RuntimeConst RuntimeConstantValue `json:"runtime_const"`          //Runtime constant values
	APIKey       string               `json:"api_key,omitempty"`      //API key for accessing Zoraxy APIs, if the plugin has permitted endpoints
	ZoraxyPort   int                  `json:"zoraxy_port,omitempty"`  //The port that Zoraxy is running on, used for making API calls to Zoraxy
	InvokeToken  string               `json:"invoke_token,omitempty"` //Secret that Zoraxy sends in the X-Zoraxy-Plugin-Token header on every call it makes to the plugin (filter / sniff). Use VerifyInvokeToken to check it

	// Contract versions this Zoraxy supports (inclusive). Only sent to plugins that declared
	// an api_version of 1 or more; APIVersionMax is 0 when Zoraxy did not send a range
	// (an older Zoraxy, or a legacy plugin). See ContractSupported.
	APIVersionMin int `json:"api_version_min,omitempty"`
	APIVersionMax int `json:"api_version_max,omitempty"`
}
    ConfigureSpec Payload

    Zoraxy will start your plugin with -configure flag, the plugin shell read
    this payload as JSON and configure itself by the supplied values like
    starting a web server at given port that listens to 127.0.0.1:port

func RecvConfigureSpec() (*ConfigureSpec, error)
    RecvExecuteConfigureSpec Function

    This function will read the configure spec from Zoraxy and return the
    ConfigureSpec object

    Place this function after ServeIntroSpect function in your plugin main
    function

func ServeAndRecvSpec(pluginSpect *IntroSpect) (*ConfigureSpec, error)
    ServeAndRecvSpec Function

    This function will serve the intro spect and return the configure spec See
    the ServeIntroSpect and RecvConfigureSpec for more details

func (c *ConfigureSpec) APIURL(endpoint string) string
    APIURL returns the address of a Zoraxy plugin API endpoint, for example
    APIURL("/plugin/api/access/list"). The endpoint may carry a query string.
    It returns an empty string, which no HTTP client can send a request to, when
    the endpoint is not a path that starts with one "/" (so "@other.host/x"
    cannot turn the address into one of another host) or when there is no port.

func (c *ConfigureSpec) ContractKnown() bool
    ContractKnown reports whether Zoraxy told the plugin which contract versions
    it supports.

func (c *ConfigureSpec) ContractSupported() bool
    ContractSupported reports whether the contract version of this package
    (APIVersion) is inside the range Zoraxy supports. It is true when Zoraxy
    sent no range (an older Zoraxy): such a Zoraxy only speaks the legacy
    contract, which every version of this package can still speak.

func (c *ConfigureSpec) DoAPIRequest(method string, endpoint string, body io.Reader) (*http.Response, error)
    DoAPIRequest builds the request as NewAPIRequest does and sends it.
    The caller closes the body of the response. Redirects are not followed and
    the call gives up after 30 seconds. A status other than 200 is not an error
    here: check resp.StatusCode (Zoraxy answers 401 for a key it does not know
    and for an endpoint that is not granted).

func (c *ConfigureSpec) NewAPIRequest(method string, endpoint string, body io.Reader) (*http.Request, error)
    NewAPIRequest builds a request to a Zoraxy plugin API endpoint with
    the Authorization header set. Send it with your own http.Client, or use
    DoAPIRequest. Set a Content-Type yourself when you send a body.

func (c *ConfigureSpec) SetAPIAuth(req *http.Request)
    SetAPIAuth sets the "Authorization: Bearer <api_key>" header on a request
    you built yourself. Only use it on requests to Zoraxy (APIURL): the key is
    a secret, and SetAPIAuth does not look at where the request goes. It does
    nothing when there is no key or no request.

func (c *ConfigureSpec) SupportsAPIVersion(version int) bool
    SupportsAPIVersion reports whether this Zoraxy supports the given contract
    version. Use it before relying on something a later contract version added.
    Without a range from Zoraxy only version 0 (legacy) is certain.

type ControlStatusCode int

const (
	ControlStatusCode_CAPTURED  ControlStatusCode = 280 //Traffic captured by plugin, ask Zoraxy not to process the traffic
	ControlStatusCode_UNHANDLED ControlStatusCode = 284 //Traffic not handled by plugin, ask Zoraxy to process the traffic
	ControlStatusCode_ERROR     ControlStatusCode = 580 //Error occurred while processing the traffic, ask Zoraxy to process the traffic and log the error
)
type DenyAction struct {
	Status  int               `json:"status,omitempty"`  //400-599, default 403
	Body    string            `json:"body,omitempty"`    //Up to 64 KiB
	Headers map[string]string `json:"headers,omitempty"` //Safe headers only (Content-Type, Cache-Control, Retry-After, ...)
}
    DenyAction is what is written to the client on "deny".

type DynamicSniffForwardRequest struct {
	Method     string              `json:"method"`
	Hostname   string              `json:"hostname"`
	URL        string              `json:"url"`
	Header     map[string][]string `json:"header"`
	RemoteAddr string              `json:"remote_addr"`
	ClientIP   string              `json:"client_ip"` //Trusted-proxy resolved client IP; use this instead of the Header or RemoteAddr fields to identify the client
	Host       string              `json:"host"`
	RequestURI string              `json:"request_uri"`
	Proto      string              `json:"proto"`
	ProtoMajor int                 `json:"proto_major"`
	ProtoMinor int                 `json:"proto_minor"`
	Rule       *SniffRuleInfo      `json:"rule,omitempty"` //The proxy rule that matched the request (additive field, absent from older Zoraxy versions)

	// Has unexported fields.
}
    A custom request object to be used in the dynamic sniffing

func DecodeForwardRequestPayload(jsonBytes []byte) (DynamicSniffForwardRequest, error)
    DecodeForwardRequestPayload decodes JSON bytes into a
    DynamicSniffForwardRequest object

func EncodeForwardRequestPayload(r *http.Request, clientIP string) DynamicSniffForwardRequest
    GetForwardRequestPayload returns a DynamicSniffForwardRequest object from
    an http.Request object. clientIP should be the trusted-proxy resolved
    client IP (e.g. from the access rule's GetClientIP), not re-derived from
    the raw request headers, otherwise a client can spoof its reported IP via
    X-Forwarded-For / X-Real-IP / etc.

func (dsfr *DynamicSniffForwardRequest) GetRequest() *http.Request
    GetRequest returns the original http.Request object, for debugging purposes

func (dsfr *DynamicSniffForwardRequest) GetRequestUUID() string
    GetRequestUUID returns the request UUID if this UUID is empty string,
    that might indicate the request is not coming from the dynamic router

type FailurePolicy string
    FailurePolicy decides what Zoraxy does with a request when the plugin cannot
    answer.

const (
	FailureOpen   FailurePolicy = "fail_open"   // default, continue as if the plugin allowed the request
	FailureClosed FailurePolicy = "fail_closed" // reject the request; needs admin consent in the Zoraxy UI
)
type FilterHandler func(*FilterRequest) *FilterVerdict
    FilterHandler is called for every filter call. Returning nil means allow.

type FilterRequest struct {
	Version       int                        `json:"version"`                  //HookAPIVersion
	Stage         HookStage                  `json:"stage"`                    //The stage being executed
	RequestID     string                     `json:"request_id"`               //Same value as the X-Zoraxy-RequestID header
	Request       DynamicSniffForwardRequest `json:"request"`                  //Sniff style description of the request (as modified by earlier stages)
	BodyPreview   []byte                     `json:"body_preview,omitempty"`   //First bytes of the body (base64 in JSON), only if requested in the manifest
	BodyTruncated bool                       `json:"body_truncated,omitempty"` //True if the body is longer than BodyPreview
	Response      *FilterResponseInfo        `json:"response,omitempty"`       //Only set at the response stage
}
    FilterRequest is the JSON body POSTed to the plugin filter endpoint.

func (f *FilterRequest) HeaderValue(name string) string
    HeaderValue returns the first value of a request header (case insensitive).

type FilterResponseInfo struct {
	Status int                 `json:"status"`
	Header map[string][]string `json:"header"`
}
    FilterResponseInfo describes the upstream response at the response stage.

type FilterVerdict struct {
	Version int           `json:"version"`          //HookAPIVersion
	Action  string        `json:"action"`           //allow | deny | modify | capture
	Reason  string        `json:"reason,omitempty"` //Free text for the Zoraxy log
	Deny    *DenyAction   `json:"deny,omitempty"`
	Modify  *ModifyAction `json:"modify,omitempty"`
}
    FilterVerdict is the JSON the plugin answers with (HTTP 200).

func Allow() *FilterVerdict
    Allow returns an "allow" verdict.

func Capture() *FilterVerdict
    Capture returns a "capture" verdict (post_auth only).

func Deny(status int, body string) *FilterVerdict
    Deny returns a "deny" verdict answering the client with status and body.

func ModifyRequestHeaders(ops HeaderOps) *FilterVerdict
    ModifyRequestHeaders returns a "modify" verdict applying request header
    operations.

func ModifyResponseHeaders(ops HeaderOps) *FilterVerdict
    ModifyResponseHeaders returns a "modify" verdict applying response header
    operations.

func (v *FilterVerdict) WithReason(reason string) *FilterVerdict
    WithReason sets the log reason and returns the verdict for chaining.

type HeaderOps struct {
	Add    map[string]string `json:"add,omitempty"`    //Append a value
	Set    map[string]string `json:"set,omitempty"`    //Replace all values
	Remove []string          `json:"remove,omitempty"` //Delete the header
}
    HeaderOps describes header changes. Names are case insensitive. Applied in
    the order remove, set, add.

type HookSettings struct {
	Version            int           `json:"version"`                        //Hooks API version the plugin was written for, use HookAPIVersion
	Stages             []HookStage   `json:"stages"`                         //Stages to register for. Empty = no filter registration
	FilterRequestPath  string        `json:"filter_request_path,omitempty"`  //Endpoint called for pre_auth / post_auth (e.g. /filter)
	FilterResponsePath string        `json:"filter_response_path,omitempty"` //Endpoint called for the response stage, defaults to FilterRequestPath
	Priority           int           `json:"priority,omitempty"`             //Lower runs first. Default 0
	TimeoutMs          int           `json:"timeout_ms,omitempty"`           //Per call timeout, default 2000, capped at 10000
	FailurePolicy      FailurePolicy `json:"failure_policy,omitempty"`       //fail_open (default) or fail_closed (needs admin consent)
	BodyPreviewBytes   int           `json:"body_preview_bytes,omitempty"`   //0 = never send a body. Max 65536
	BodyContentTypes   []string      `json:"body_content_types,omitempty"`   //Media types that get a body preview, e.g. application/json, text/*. Empty = none
}
    HookSettings is the optional "hooks" object of the introspection payload.

func (h *HookSettings) EffectiveBodyPreviewBytes() int
    EffectiveBodyPreviewBytes returns the body preview size after clamping to
    [0, MaxBodyPreviewBytes].

func (h *HookSettings) EffectiveTimeout() time.Duration
    EffectiveTimeout returns the call timeout after applying default and cap.

func (h *HookSettings) HasStage(s HookStage) bool
    HasStage reports whether the plugin registered for the stage.

func (h *HookSettings) PathForStage(s HookStage) string
    PathForStage returns the filter endpoint for the stage ("" if none).

func (h *HookSettings) WantsBodyFor(contentType string) bool
    WantsBodyFor reports whether a body with the given Content-Type header
    should be previewed.

type HookStage string
    HookStage is a point in the request pipeline a plugin can register for.

const (
	HookStagePreAuth  HookStage = "pre_auth"
	HookStagePostAuth HookStage = "post_auth"
	HookStageResponse HookStage = "response"
)
type IntroSpect struct {
	//  Plugin metadata
	ID            string     `json:"id"`             //Unique ID of your plugin, recommended using your own domain in reverse like com.yourdomain.pluginname
	Name          string     `json:"name"`           //Name of your plugin
	Author        string     `json:"author"`         //Author name of your plugin
	AuthorContact string     `json:"author_contact"` //Author contact of your plugin, like email
	Description   string     `json:"description"`    //Description of your plugin
	URL           string     `json:"url"`            //URL of your plugin
	Type          PluginType `json:"type"`           //Type of your plugin, Router(0) or Utilities(1)
	VersionMajor  int        `json:"version_major"`  //Major version of your plugin
	VersionMinor  int        `json:"version_minor"`  //Minor version of your plugin
	VersionPatch  int        `json:"version_patch"`  //Patch version of your plugin

	//		Static Capture Settings
	//
	//		Once plugin is enabled these rules always applies to the enabled HTTP Proxy rule
	//		This is faster than dynamic capture, but less flexible

	StaticCapturePaths   []StaticCaptureRule `json:"static_capture_paths"`   //Static capture paths of your plugin, see Zoraxy documentation for more details
	StaticCaptureIngress string              `json:"static_capture_ingress"` //Static capture ingress path of your plugin (e.g. /s_handler)

	//		Dynamic Capture Settings
	//
	//		Once plugin is enabled, these rules will be captured and forward to plugin sniff
	//		if the plugin sniff returns 280, the traffic will be captured
	//		otherwise, the traffic will be forwarded to the next plugin
	//		This is slower than static capture, but more flexible

	DynamicCaptureSniff   string `json:"dynamic_capture_sniff"`   //Dynamic capture sniff path of your plugin (e.g. /d_sniff)
	DynamicCaptureIngress string `json:"dynamic_capture_ingress"` //Dynamic capture ingress path of your plugin (e.g. /d_handler)

	//  UI Path for your plugin
	UIPath string `json:"ui_path"` //UI path of your plugin (e.g. /ui), will proxy the whole subpath tree to Zoraxy Web UI as plugin UI

	//  Subscriptions Settings
	SubscriptionPath    string            `json:"subscription_path"`    //Subscription event path of your plugin (e.g. /notifyme), a POST request with SubscriptionEvent as body will be sent to this path when the event is triggered
	SubscriptionsEvents map[string]string `json:"subscriptions_events"` //Subscriptions events of your plugin, paired with comments describing how the event is used, see Zoraxy documentation for more details

	//  API Access Control
	PermittedAPIEndpoints []PermittedAPIEndpoint `json:"permitted_api_endpoints"` //List of API endpoints this plugin can access, and a description of why the plugin needs to access this endpoint

	//		Request / Response Hooks (optional, since hooks API version 1)
	//
	//		Lets the plugin act as a middleware / WAF style filter. Omit (nil) for a legacy
	//		plugin, see hooks.go for details. Old Zoraxy versions ignore this field.

	Hooks *HookSettings `json:"hooks,omitempty"`

	//		Supervision (optional, old Zoraxy versions ignore these fields)
	//
	//		HealthPath: a path of your plugin that answers a GET with any 2xx status while
	//		the plugin works (e.g. /health). Zoraxy only calls it when the administrator
	//		turned the health check of the plugin on. Without it the health check is a
	//		TCP connect to your port, which cannot see a plugin that accepts connections
	//		but no longer answers.
	//
	//		ConfigureVia: set to ConfigureViaStdin and Zoraxy starts your plugin with the
	//		flag -configure-stdin and writes the configure payload (one JSON document) to
	//		its standard input instead of putting it on the command line, where every
	//		local user can read your API key. RecvConfigureSpec handles both ways.

	HealthPath   string `json:"health_path,omitempty"`
	ConfigureVia string `json:"configure_via,omitempty"`

	//		Contract version (optional, old Zoraxy versions ignore this field)
	//
	//		The version of the plugin contract your plugin was built for. Leave it 0 and
	//		ServeIntroSpect fills in the APIVersion of this package. A plugin without the
	//		field is a legacy plugin: Zoraxy runs it exactly as before. Zoraxy warns the
	//		administrator when a plugin was built for a newer contract than it supports,
	//		and refuses to start it only when the administrator asked for that.

	APIVersion int `json:"api_version,omitempty"`
}
    IntroSpect Payload

    When the plugin is initialized with -introspect flag, the plugin shell
    return this payload as JSON and exit

type ModifyAction struct {
	RequestHeaders  *HeaderOps `json:"request_headers,omitempty"`  //Request stages only
	Path            *string    `json:"path,omitempty"`             //Request stages only. Absolute path, same host
	Query           *string    `json:"query,omitempty"`            //Request stages only. Raw query without leading ?
	ResponseHeaders *HeaderOps `json:"response_headers,omitempty"` //Response stage only
}
    ModifyAction is applied on "modify".

type PathRouter struct {
	// Has unexported fields.
}

func NewPathRouter() *PathRouter
    NewPathRouter creates a new PathRouter

func (p *PathRouter) PrintRequestDebugMessage(r *http.Request)

func (p *PathRouter) RegisterDynamicCaptureHandle(capture_ingress string, mux *http.ServeMux, handlefunc func(http.ResponseWriter, *http.Request))
    RegisterDynamicCaptureHandle register the dynamic capture ingress path with
    a handler

func (p *PathRouter) RegisterDynamicSniffHandler(sniff_ingress string, mux *http.ServeMux, handler SniffHandler)
    RegisterDynamicSniffHandler registers a dynamic sniff handler for a path
    You can decide to accept or skip the request based on the request header and
    paths

func (p *PathRouter) RegisterPathHandler(path string, handler http.Handler)
    RegisterPathHandler registers a handler for a path

func (p *PathRouter) RegisterStaticCaptureHandle(capture_ingress string, mux *http.ServeMux)
    StartStaticCapture starts the static capture ingress

func (p *PathRouter) RemovePathHandler(path string)
    RemovePathHandler removes a handler for a path

func (p *PathRouter) SetDebugPrintMode(enable bool)
    SetDebugPrintMode sets the debug print mode

func (p *PathRouter) SetDefaultHandler(handler http.Handler)
    SetDefaultHandler sets the default handler for the router This handler will
    be called if no path handler is found

type PermittedAPIEndpoint struct {
	Method   string `json:"method"`   //HTTP method for the API endpoint (e.g., GET, POST)
	Endpoint string `json:"endpoint"` //The API endpoint that the plugin can access
	Reason   string `json:"reason"`   //The reason why the plugin needs to access this endpoint
}

type PluginType int

const (
	PluginType_Router    PluginType = 0 //Router Plugin, used for handling / routing / forwarding traffic
	PluginType_Utilities PluginType = 1 //Utilities Plugin, used for utilities like Zerotier or Static Web Server that do not require interception with the dpcore
)
type PluginUiDebugRouter struct {
	PluginID      string //The ID of the plugin
	TargetDir     string //The directory where the UI files are stored
	HandlerPrefix string //The prefix of the handler used to route this router, e.g. /ui
	EnableDebug   bool   //Enable debug mode
	// Has unexported fields.
}

func NewPluginFileSystemUIRouter(pluginID string, targetDir string, handlerPrefix string) *PluginUiDebugRouter
    NewPluginFileSystemUIRouter creates a new PluginUiRouter with file system
    The targetDir is the directory where the UI files are stored (e.g. ./www)
    The handlerPrefix is the prefix of the handler used to route this router
    The handlerPrefix should start with a slash (e.g. /ui) that matches the
    http.Handle path All prefix should not end with a slash

func (p *PluginUiDebugRouter) AttachHandlerToMux(mux *http.ServeMux)
    Attach the file system UI handler to the target http.ServeMux

func (p *PluginUiDebugRouter) Handler() http.Handler
    GetHttpHandler returns the http.Handler for the PluginUiRouter

func (p *PluginUiDebugRouter) RegisterTerminateHandler(termFunc func(), mux *http.ServeMux)
    RegisterTerminateHandler registers the terminate handler for the
    PluginUiRouter The terminate handler will be called when the plugin is
    terminated from Zoraxy plugin manager if mux is nil, the handler will be
    registered to http.DefaultServeMux

type PluginUiRouter struct {
	PluginID       string    //The ID of the plugin
	TargetFs       *embed.FS //The embed.FS where the UI files are stored
	TargetFsPrefix string    //The prefix of the embed.FS where the UI files are stored, e.g. /web
	HandlerPrefix  string    //The prefix of the handler used to route this router, e.g. /ui
	EnableDebug    bool      //Enable debug mode
	// Has unexported fields.
}

func NewPluginEmbedUIRouter(pluginID string, targetFs *embed.FS, targetFsPrefix string, handlerPrefix string) *PluginUiRouter
    NewPluginEmbedUIRouter creates a new PluginUiRouter with embed.FS The
    targetFsPrefix is the prefix of the embed.FS where the UI files are stored
    The targetFsPrefix should be relative to the root of the embed.FS The
    targetFsPrefix should start with a slash (e.g. /web) that corresponds to the
    root folder of the embed.FS The handlerPrefix is the prefix of the handler
    used to route this router The handlerPrefix should start with a slash (e.g.
    /ui) that matches the http.Handle path All prefix should not end with a
    slash

func (p *PluginUiRouter) AttachHandlerToMux(mux *http.ServeMux)
    Attach the embed UI handler to the target http.ServeMux

func (p *PluginUiRouter) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request), mux *http.ServeMux)
    HandleFunc registers a handler function for the given pattern The pattern
    should start with the handler prefix, e.g. /ui/hello If the pattern does not
    start with the handler prefix, it will be prepended with the handler prefix

func (p *PluginUiRouter) Handler() http.Handler
    GetHttpHandler returns the http.Handler for the PluginUiRouter

func (p *PluginUiRouter) RegisterTerminateHandler(termFunc func(), mux *http.ServeMux)
    RegisterTerminateHandler registers the terminate handler for the
    PluginUiRouter The terminate handler will be called when the plugin is
    terminated from Zoraxy plugin manager if mux is nil, the handler will be
    registered to http.DefaultServeMux

type RuntimeConstantValue struct {
	ZoraxyVersion    string `json:"zoraxy_version"`
	ZoraxyUUID       string `json:"zoraxy_uuid"`
	DevelopmentBuild bool   `json:"development_build"` //Whether the Zoraxy is a development build or not
}

type SniffHandler func(*DynamicSniffForwardRequest) SniffResult

type SniffResult int

const (
	SniffResultAccept SniffResult = iota // Forward the request to this plugin dynamic capture ingress
	SniffResultSkip                      // Skip this plugin and let the next plugin handle the request
)
type SniffRuleInfo struct {
	Name string   `json:"name"` //The matching domain (or root) of the rule, as shown in the Zoraxy UI
	UUID string   `json:"uuid"` //Stable identifier derived from the rule key (rules have no stored UUID); changes only if the rule is renamed
	Tags []string `json:"tags"` //Tags of the rule (the plugin was selected by these)
}
        Sniffing and forwarding

        The following functions are here to help with
        sniffing and forwarding requests to the dynamic
        router.

    SniffRuleInfo tells a dynamic capture plugin which proxy rule matched the
    request

type StaticCaptureRule struct {
	CapturePath string `json:"capture_path"`
}

type SubscriptionEvent struct {
	EventName   string `json:"event_name"`
	EventSource string `json:"event_source"`
	Payload     string `json:"payload"` //Payload of the event, can be empty
}

</code></pre>
