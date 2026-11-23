package plugins

import (
	_ "embed"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
	"imuslab.com/zoraxy/mod/info/logger"
	zoraxyPlugin "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

//go:embed no_img.png
var noImg []byte

type Plugin struct {
	RootDir string                   //The root directory of the plugin
	Spec    *zoraxyPlugin.IntroSpect //The plugin specification
	Enabled bool                     //Whether the plugin is enabled (its process is running). Guarded by mu once the plugin is loaded, use isEnabled()

	//Runtime, guarded by mu (see status.go)
	mu                sync.RWMutex
	lifeMu            sync.Mutex                      //serialises StartPlugin / StopPlugin of this plugin
	proc              *pluginProc                     //the running process, nil when not running
	status            pluginStatusRecord              //read-only status shown by the API
	obs               pluginObserved                  //last-seen and call counters (atomics)
	startGrace        time.Duration                   //test override of defaultStartGrace
	AssignedPort      int                             //The assigned port for the plugin
	uiProxy           *dpcore.ReverseProxy            //The reverse proxy for the plugin UI
	staticRouteProxy  map[string]*dpcore.ReverseProxy //Storing longest prefix => dpcore map for static route
	dynamicRouteProxy *dpcore.ReverseProxy            //The reverse proxy for the dynamic route
	SupportHotRebuild bool                            //Whether the plugin source code exists in the plugin folder tree
	hook              hookRuntime                     //Hook / filter runtime state (admin settings, circuit breaker, invoke token)

	//Phase 1: supervision (see supervisor.go, policy.go)
	mgr        *Manager        //guarded by mu: the manager that started the plugin last (for log lines from the event worker)
	notReady   bool            //guarded by mu: the readiness gate of the running plugin still waits for its port, so it is not in the request path yet
	wantDown   bool            //guarded by mu: the last thing the administrator (or an update / rebuild) did was stop the plugin, so it is not "down" for block-when-down
	polMu      sync.RWMutex    //guards pol
	pol        PluginPolicy    //what the administrator allows Zoraxy to do about this plugin, zero value = behaviour without supervision
	sup        supervisorState //restart backoff, crash loop and exit history
	capBreaker captureBreaker  //circuit breaker of the capture and UI paths (only enforced with a capture timeout)
	evq        eventQueue      //bounded queue of events waiting to be sent to the plugin
	logw       pluginLogFile   //per plugin log file (only with LogTarget = file)
}

type ManagerOptions struct {
	/* Plugins */
	PluginDir          string              //The directory where the plugins are stored
	PluginGroups       map[string][]string //The plugin groups,key is the tag name and the value is an array of plugin IDs
	PluginGroupsConfig string              //The group / tag configuration file, if set the plugin groups will be loaded from this file

	/* Plugin Downloader */
	PluginStoreURLs         []string              //The plugin store URLs, used to download the plugins
	DownloadablePluginCache []*DownloadablePlugin //The cache for the downloadable plugins, key is the plugin ID and value is the DownloadablePlugin struct
	LastSuccPluginSyncTime  int64                 //The last sync time for the plugin store URLs, used to check if the plugin store URLs need to be synced again

	/* Run plugins as an unprivileged OS user (Unix only, requires root, see runas_unix.go). Empty = same user as Zoraxy */
	RunAsUser  string
	RunAsGroup string

	/* Runtime */
	SystemConst  *zoraxyPlugin.RuntimeConstantValue //The system constant value
	ZoraxyPort   int                                //The port of the Zoraxy instance, used for API calls
	CSRFTokenGen func(*http.Request) string         `json:"-"` //The CSRF token generator function
	Database     *database.Database                 `json:"-"`
	Logger       *logger.Logger                     `json:"-"`

	/* API Key Management */
	APIKeyManager *auth.APIKeyManager `json:"-"` //The API key manager for the plugins

	/* Per plugin log files (only used by plugins whose policy says LogTarget = file). Empty = "plugins" inside the log folder of Logger, or ./log/plugins */
	PluginLogDir string

	/* Status */
	ProbePluginPorts bool //Off by default. On: listing plugins opens one TCP connection to the port of every running plugin (cached 2 s) to tell "starting" / "not listening" from "running"

	/* Development */
	EnableHotReload       bool //Check if the plugin file is changed and reload the plugin automatically
	EnablePluginAutoBuild bool //Enable automatic build for the plugin when the plugin is started
	HotReloadInterval     int  //The interval for checking the plugin file change, in seconds
}

type Manager struct {
	LoadedPlugins      map[string]*Plugin   //Storing *Plugin
	tagPluginMap       sync.Map             //Storing *radix.Tree for each plugin tag
	tagPluginListMutex sync.RWMutex         //Mutex for the tagPluginList
	tagPluginList      map[string][]*Plugin //Storing the plugin list for each tag, only concurrent read is allowed
	Options            *ManagerOptions

	PluginHash map[string]string //The hash of the plugin file, used to check if the plugin file is changed

	/* Internal */
	loadedPluginsMutex sync.RWMutex //Mutex for the loadedPlugins
	pluginGroupsMutex  sync.RWMutex //Mutex for the pluginGroups
	pluginCheckMutex   sync.RWMutex //Mutex for the plugin hash
	pluginReloadTicker *time.Ticker //Ticker for the plugin reload
	pluginReloadStop   chan bool    //Channel to stop the plugin reload ticker

	hookCfg hookTunables //Circuit breaker tunables, zero value = defaults

	stopGrace         time.Duration          //time a plugin gets to stop after SIGTERM, zero value = defaultStopGrace
	loadFailuresMutex sync.Mutex             //Mutex for loadFailures
	loadFailures      map[string]LoadFailure //plugin folders that could not be loaded, key is the folder name

	exitDrainHook func() //tests only: runs in the exit watcher after the output drain

	supCfg  supTunables //supervisor tunables, zero value = defaults (tests shorten them)
	closing atomic.Bool //Close() was called: no automatic restart any more
}
