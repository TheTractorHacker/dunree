package dunree_plugin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

/*
	Plugins Includes.go

	This file is copied from Dunree source code
	You can always find the latest version under mod/plugins/dunree_plugin
	The package follows semantic versioning (SDKVersion below, CHANGELOG.md):
	a plugin built with an older 1.x copy keeps working with a newer Dunree.
*/

// SDK and contract version
//
// SDKVersion is the version of this package (semantic versioning, see CHANGELOG.md
// next to this file). It changes with every release of the package.
//
// APIVersion is the version of the plugin contract this package implements: what
// Dunree and a plugin say to each other (introspect, configure, calls, events).
// It only changes when the contract itself changes in a way a plugin or Dunree has
// to know about. The written contract is docs/plugins/contract.md in the Dunree
// repository. A plugin that declares no api_version is a "legacy" plugin (version 0)
// and keeps working.
const (
	SDKVersion = "2.0.0"
	APIVersion = 1
)

type PluginType int

const (
	PluginType_Router    PluginType = 0 //Router Plugin, used for handling / routing / forwarding traffic
	PluginType_Utilities PluginType = 1 //Utilities Plugin, used for utilities like Zerotier or Static Web Server that do not require interception with the dpcore
)

type StaticCaptureRule struct {
	CapturePath string `json:"capture_path"`
	//To be expanded
}

type ControlStatusCode int

const (
	ControlStatusCode_CAPTURED  ControlStatusCode = 280 //Traffic captured by plugin, ask Dunree not to process the traffic
	ControlStatusCode_UNHANDLED ControlStatusCode = 284 //Traffic not handled by plugin, ask Dunree to process the traffic
	ControlStatusCode_ERROR     ControlStatusCode = 580 //Error occurred while processing the traffic, ask Dunree to process the traffic and log the error
)

type SubscriptionEvent struct {
	EventName   string `json:"event_name"`
	EventSource string `json:"event_source"`
	Payload     string `json:"payload"` //Payload of the event, can be empty
}

/*
RuntimeConstantValue is the "runtime_const" object of the configure payload.

Dunree sends dunree_version and dunree_uuid to a plugin that declared sdk_flavor "dunree"
(ServeIntroSpect does that for you). It also sends the fields a plugin built with the Zoraxy // legacy-compat
SDK reads: zoraxy_uuid (the same value) and zoraxy_version, which is the Zoraxy release this // legacy-compat
Dunree is based on (for example 3.3.6), not the Dunree version.

When this package runs on a host that only sends the zoraxy_* fields (upstream Zoraxy), // legacy-compat
DunreeVersion and DunreeUUID are filled from them, so read the Dunree* fields.
*/
type RuntimeConstantValue struct {
	DunreeVersion    string `json:"dunree_version,omitempty"` //Version of Dunree (on a Zoraxy host: the Zoraxy version) // legacy-compat
	DunreeUUID       string `json:"dunree_uuid,omitempty"`    //Node UUID of the host
	ZoraxyVersion    string `json:"zoraxy_version"`           //Legacy field: the Zoraxy release the host is, or is based on // legacy-compat
	ZoraxyUUID       string `json:"zoraxy_uuid"`              //Legacy field: the node UUID // legacy-compat
	DevelopmentBuild bool   `json:"development_build"`        //Whether the Dunree is a development build or not
}

// SDKFlavorDunree is the value of IntroSpect.SDKFlavor this package declares
const SDKFlavorDunree = "dunree"

type PermittedAPIEndpoint struct {
	Method   string `json:"method"`   //HTTP method for the API endpoint (e.g., GET, POST)
	Endpoint string `json:"endpoint"` //The API endpoint that the plugin can access
	Reason   string `json:"reason"`   //The reason why the plugin needs to access this endpoint
}

/*
IntroSpect Payload

When the plugin is initialized with -introspect flag,
the plugin shell return this payload as JSON and exit
*/
type IntroSpect struct {
	/* Plugin metadata */
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

	/*

		Endpoint Settings

	*/

	/*
		Static Capture Settings

		Once plugin is enabled these rules always applies to the enabled HTTP Proxy rule
		This is faster than dynamic capture, but less flexible
	*/
	StaticCapturePaths   []StaticCaptureRule `json:"static_capture_paths"`   //Static capture paths of your plugin, see Dunree documentation for more details
	StaticCaptureIngress string              `json:"static_capture_ingress"` //Static capture ingress path of your plugin (e.g. /s_handler)

	/*
		Dynamic Capture Settings

		Once plugin is enabled, these rules will be captured and forward to plugin sniff
		if the plugin sniff returns 280, the traffic will be captured
		otherwise, the traffic will be forwarded to the next plugin
		This is slower than static capture, but more flexible
	*/
	DynamicCaptureSniff   string `json:"dynamic_capture_sniff"`   //Dynamic capture sniff path of your plugin (e.g. /d_sniff)
	DynamicCaptureIngress string `json:"dynamic_capture_ingress"` //Dynamic capture ingress path of your plugin (e.g. /d_handler)

	/* UI Path for your plugin */
	UIPath string `json:"ui_path"` //UI path of your plugin (e.g. /ui), will proxy the whole subpath tree to Dunree Web UI as plugin UI

	/* Subscriptions Settings */
	SubscriptionPath    string            `json:"subscription_path"`    //Subscription event path of your plugin (e.g. /notifyme), a POST request with SubscriptionEvent as body will be sent to this path when the event is triggered
	SubscriptionsEvents map[string]string `json:"subscriptions_events"` //Subscriptions events of your plugin, paired with comments describing how the event is used, see Dunree documentation for more details

	/* API Access Control */
	PermittedAPIEndpoints []PermittedAPIEndpoint `json:"permitted_api_endpoints"` //List of API endpoints this plugin can access, and a description of why the plugin needs to access this endpoint

	/*
		Request / Response Hooks (optional, since hooks API version 1)

		Lets the plugin act as a middleware / WAF style filter. Omit (nil) for a legacy
		plugin, see hooks.go for details. Old Dunree versions ignore this field.
	*/
	Hooks *HookSettings `json:"hooks,omitempty"`

	/*
		Supervision (optional, old Dunree versions ignore these fields)

		HealthPath: a path of your plugin that answers a GET with any 2xx status while
		the plugin works (e.g. /health). Dunree only calls it when the administrator
		turned the health check of the plugin on. Without it the health check is a
		TCP connect to your port, which cannot see a plugin that accepts connections
		but no longer answers.

		ConfigureVia: set to ConfigureViaStdin and Dunree starts your plugin with the
		flag -configure-stdin and writes the configure payload (one JSON document) to
		its standard input instead of putting it on the command line, where every
		local user can read your API key. RecvConfigureSpec handles both ways.
	*/
	HealthPath   string `json:"health_path,omitempty"`
	ConfigureVia string `json:"configure_via,omitempty"`

	/*
		Contract version (optional, old Dunree versions ignore this field)

		The version of the plugin contract your plugin was built for. Leave it 0 and
		ServeIntroSpect fills in the APIVersion of this package. A plugin without the
		field is a legacy plugin: Dunree runs it exactly as before. Dunree warns the
		administrator when a plugin was built for a newer contract than it supports,
		and refuses to start it only when the administrator asked for that.
	*/
	APIVersion int `json:"api_version,omitempty"`

	/*
		SDK flavour (optional, Zoraxy and old Dunree versions ignore this field) // legacy-compat

		Leave it empty and ServeIntroSpect fills in SDKFlavorDunree. It tells Dunree that the
		plugin reads the Dunree names of the configure payload (dunree_port, dunree_version,
		dunree_uuid), which are then sent next to the legacy zoraxy_* fields. A plugin without
		the field gets the payload a Zoraxy plugin always got. // legacy-compat
	*/
	SDKFlavor string `json:"sdk_flavor,omitempty"`
}

const (
	ConfigureViaStdin  = "stdin"            //value of IntroSpect.ConfigureVia
	ConfigureStdinFlag = "-configure-stdin" //flag a plugin is started with when it declared ConfigureViaStdin
	maxConfigureBytes  = 1 << 20
)

/*
ServeIntroSpect Function

This function will check if the plugin is initialized with -introspect flag,
if so, it will print the intro spect and exit

Place this function at the beginning of your plugin main function
*/
func ServeIntroSpect(pluginSpect *IntroSpect) {
	if len(os.Args) > 1 && os.Args[1] == "-introspect" {
		//Print the intro spect and exit
		out := *pluginSpect
		if out.APIVersion == 0 {
			//Built with this package = speaks the contract version of this package
			out.APIVersion = APIVersion
		}
		if out.SDKFlavor == "" {
			out.SDKFlavor = SDKFlavorDunree
		}
		jsonData, _ := json.MarshalIndent(&out, "", " ")
		fmt.Println(string(jsonData))
		os.Exit(0)
	}
}

/*
ConfigureSpec Payload

Dunree will start your plugin with -configure flag,
the plugin shell read this payload as JSON and configure itself
by the supplied values like starting a web server at given port
that listens to 127.0.0.1:port
*/
type ConfigureSpec struct {
	Port         int                  `json:"port"`                   //Port to listen
	RuntimeConst RuntimeConstantValue `json:"runtime_const"`          //Runtime constant values
	APIKey       string               `json:"api_key,omitempty"`      //API key for accessing Dunree APIs, if the plugin has permitted endpoints
	DunreePort   int                  `json:"dunree_port,omitempty"`  //The port that Dunree is running on, used for making API calls to Dunree (on a Zoraxy host: filled from zoraxy_port) // legacy-compat
	ZoraxyPort   int                  `json:"zoraxy_port,omitempty"`  //Legacy field with the same port, what a plugin built with the Zoraxy SDK reads. Use DunreePort // legacy-compat
	InvokeToken  string               `json:"invoke_token,omitempty"` //Secret that Dunree sends in the X-Dunree-Plugin-Token header (and X-Zoraxy-Plugin-Token) on every call it makes to the plugin (filter / sniff). Use VerifyInvokeToken to check it

	//Contract versions this Dunree supports (inclusive). Only sent to plugins that declared
	//an api_version of 1 or more; APIVersionMax is 0 when Dunree did not send a range
	//(an older Dunree, or a legacy plugin). See ContractSupported.
	APIVersionMin int `json:"api_version_min,omitempty"`
	APIVersionMax int `json:"api_version_max,omitempty"`
	//To be expanded
}

// UnmarshalJSON reads a configure payload from Dunree or from Zoraxy. A host that only sends the // legacy-compat
// legacy names (zoraxy_port, runtime_const.zoraxy_version, runtime_const.zoraxy_uuid) fills the
// Dunree fields too, so plugin code reads DunreePort, DunreeVersion and DunreeUUID on every host.
func (c *ConfigureSpec) UnmarshalJSON(data []byte) error {
	type plain ConfigureSpec //no methods: no recursion
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*c = ConfigureSpec(p)
	c.fillFromLegacy()
	return nil
}

func (c *ConfigureSpec) fillFromLegacy() {
	if c.DunreePort == 0 {
		c.DunreePort = c.ZoraxyPort // legacy-compat
	}
	if c.RuntimeConst.DunreeVersion == "" {
		c.RuntimeConst.DunreeVersion = c.RuntimeConst.ZoraxyVersion // legacy-compat
	}
	if c.RuntimeConst.DunreeUUID == "" {
		c.RuntimeConst.DunreeUUID = c.RuntimeConst.ZoraxyUUID // legacy-compat
	}
}

// ContractKnown reports whether Dunree told the plugin which contract versions it supports.
func (c *ConfigureSpec) ContractKnown() bool {
	return c != nil && c.APIVersionMax > 0
}

// ContractSupported reports whether the contract version of this package (APIVersion)
// is inside the range Dunree supports. It is true when Dunree sent no range (an older
// Dunree): such a Dunree only speaks the legacy contract, which every version of this
// package can still speak.
func (c *ConfigureSpec) ContractSupported() bool {
	if !c.ContractKnown() {
		return true
	}
	return APIVersion >= c.APIVersionMin && APIVersion <= c.APIVersionMax
}

// SupportsAPIVersion reports whether this Dunree supports the given contract version.
// Use it before relying on something a later contract version added. Without a range
// from Dunree only version 0 (legacy) is certain.
func (c *ConfigureSpec) SupportsAPIVersion(version int) bool {
	if !c.ContractKnown() {
		return version == 0
	}
	return version >= c.APIVersionMin && version <= c.APIVersionMax
}

// warnContract prints one line when Dunree does not support the contract of this package
func warnContract(c *ConfigureSpec) {
	if !c.ContractSupported() {
		fmt.Fprintf(os.Stderr, "dunree_plugin: this plugin was built for plugin contract version %d (SDK %s), this Dunree supports %d to %d. It may not work as expected.\n", APIVersion, SDKVersion, c.APIVersionMin, c.APIVersionMax)
	}
}

/*
HealthHandler returns a handler for the path you declared as IntroSpect.HealthPath.

It answers 200 "ok" while check returns nil and 503 otherwise (the text of the
error is not sent). Pass nil when being able to answer is all there is to check.
Keep check fast: Dunree gives a health check 2 seconds.
*/
func HealthHandler(check func() error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if check != nil {
			if err := check(); err != nil {
				http.Error(w, "unhealthy", http.StatusServiceUnavailable)
				return
			}
		}
		w.Write([]byte("ok"))
	})
}

/*
RecvExecuteConfigureSpec Function

This function will read the configure spec from Dunree
and return the ConfigureSpec object

Place this function after ServeIntroSpect function in your plugin main function
*/
func RecvConfigureSpec() (*ConfigureSpec, error) {
	for i, arg := range os.Args {
		if arg == ConfigureStdinFlag {
			//The payload is on the standard input (see IntroSpect.ConfigureVia)
			raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxConfigureBytes))
			if err != nil {
				return nil, err
			}
			var configSpec ConfigureSpec
			if err := json.Unmarshal(raw, &configSpec); err != nil {
				return nil, err
			}
			warnContract(&configSpec)
			return &configSpec, nil
		}
		if strings.HasPrefix(arg, "-configure=") {
			var configSpec ConfigureSpec
			if err := json.Unmarshal([]byte(arg[11:]), &configSpec); err != nil {
				return nil, err
			}
			warnContract(&configSpec)
			return &configSpec, nil
		} else if arg == "-configure" {
			var configSpec ConfigureSpec
			var nextArg string
			if len(os.Args) > i+1 {
				nextArg = os.Args[i+1]
				if err := json.Unmarshal([]byte(nextArg), &configSpec); err != nil {
					return nil, err
				}
			} else {
				return nil, fmt.Errorf("no port specified after -configure flag")
			}
			warnContract(&configSpec)
			return &configSpec, nil
		}
	}
	return nil, fmt.Errorf("no -configure flag found")
}

/*
ServeAndRecvSpec Function

This function will serve the intro spect and return the configure spec
See the ServeIntroSpect and RecvConfigureSpec for more details
*/
func ServeAndRecvSpec(pluginSpect *IntroSpect) (*ConfigureSpec, error) {
	ServeIntroSpect(pluginSpect)
	return RecvConfigureSpec()
}
