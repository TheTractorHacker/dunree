package main

import (
	"fmt"
	"github.com/foleyit/dunree/mod/offline"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/foleyit/dunree/mod/auth/sso/oauth2"
	"github.com/foleyit/dunree/mod/eventsystem"

	"github.com/foleyit/dunree/mod/access"
	"github.com/foleyit/dunree/mod/acme"
	"github.com/foleyit/dunree/mod/auth"
	"github.com/foleyit/dunree/mod/auth/sso/forward"
	"github.com/foleyit/dunree/mod/auth/sso/zorxauth"
	"github.com/foleyit/dunree/mod/cluster"
	"github.com/foleyit/dunree/mod/database"
	"github.com/foleyit/dunree/mod/database/dbinc"
	"github.com/foleyit/dunree/mod/dockerux"
	"github.com/foleyit/dunree/mod/dynamicproxy/loadbalance"
	"github.com/foleyit/dunree/mod/dynamicproxy/redirection"
	"github.com/foleyit/dunree/mod/forwardproxy"
	"github.com/foleyit/dunree/mod/geodb"
	"github.com/foleyit/dunree/mod/info/hardwareinfo"
	"github.com/foleyit/dunree/mod/info/logger"
	"github.com/foleyit/dunree/mod/info/logviewer"
	"github.com/foleyit/dunree/mod/info/shellexec"
	"github.com/foleyit/dunree/mod/info/usageinfo"
	"github.com/foleyit/dunree/mod/mdns"
	"github.com/foleyit/dunree/mod/netstat"
	"github.com/foleyit/dunree/mod/pathrule"
	"github.com/foleyit/dunree/mod/plugins"
	"github.com/foleyit/dunree/mod/secaudit"
	"github.com/foleyit/dunree/mod/sshprox"
	"github.com/foleyit/dunree/mod/statistic"
	"github.com/foleyit/dunree/mod/statistic/analytic"
	"github.com/foleyit/dunree/mod/streamproxy"
	"github.com/foleyit/dunree/mod/tlscert"
	"github.com/foleyit/dunree/mod/webserv"
	"github.com/foleyit/dunree/mod/wirecompat"
	"github.com/gorilla/csrf"
)

/*
	Startup Sequence

	This function starts the startup sequence of all
	required modules. Their startup sequences are inter-dependent
	and must be started in a specific order.

	Don't touch this function unless you know what you are doing
*/

func startupSequence() {
	//Start a system wide logger and log viewer
	l, err := logger.NewLogger(LOG_PREFIX, *path_logFile)
	if err == nil {
		SystemWideLogger = l
	} else {
		panic(err)
	}

	if !*enableLog {
		//Disable file logging, use fmt logger instead
		l, err = logger.NewFmtLogger()
		if err != nil {
			panic(err)
		}
		SystemWideLogger = l
		SystemWideLogger.Println("System wide logging is disabled, all logs will be printed to STDOUT only")
	} else {
		// Load log configuration from file
		logConfig, err := logger.LoadLogConfig(CONF_LOG_CONFIG)
		if err != nil {
			SystemWideLogger.Println("Failed to load log config, using defaults: " + err.Error())
			logConfig = &logger.LogConfig{
				Enabled:  false,
				MaxSize:  "0",
				Compress: true,
			}
		}

		// Apply the configuration
		if err := l.ApplyLogConfig(logConfig); err != nil {
			SystemWideLogger.Println("Failed to apply log config: " + err.Error())
		}

		SystemWideLogger = l
		if !logConfig.Enabled {
			SystemWideLogger.Println("Log rotation is disabled")
		} else {
			SystemWideLogger.Println("Log rotation is enabled, max log file size " + logConfig.MaxSize)
		}
		SystemWideLogger.Println("System wide logging is enabled")
	}

	initWAFAuditLog() //WAF JSON audit log, see wafapi.go
	initSiteLogs()    //Optional per-site request logs, see sitelogapi.go

	LogViewer = logviewer.NewLogViewer(&logviewer.ViewerOption{
		RootFolder: *path_logFile,
	})

	//Create database
	backendType := database.GetRecommendedBackendType()
	switch *databaseBackend {
	case "leveldb":
		backendType = dbinc.BackendLevelDB
	case "boltdb":
		backendType = dbinc.BackendBoltDB
	}
	l.PrintAndLog("database", "Using "+backendType.String()+" as the database backend", nil)
	db, err := database.NewDatabase(*path_database, backendType)
	if err != nil {
		reportDatabaseOpenError(l, err)
	}
	sysdb = db
	//Create tables for the database
	sysdb.NewTable("settings")
	initSecurityAudit() //security audit log (conf/security_audit.log), see securityaudit.go
	initHistory()       //change history store; finishes an interrupted restore before modules read their files
	initAdminExposure() //destination guard and admin allow-list (both off until configured), see adminexposure.go
	//Cluster follower with "sync settings": bring the primary's database-stored settings in before modules read them (cluster_settings.go)
	clusterImportSettings()
	initWireCompat() //"Also send legacy X-Zoraxy-* headers" (on unless switched off), see wirecompatapi.go

	//Create tmp folder and conf folder
	os.MkdirAll(TMP_FOLDER, 0775)
	os.MkdirAll(CONF_HTTP_PROXY, 0775)

	//Create an auth agent
	sessionKey, err := auth.GetSessionKey(sysdb, SystemWideLogger)
	if err != nil {
		log.Fatal(err)
	}
	authAgent = auth.NewAuthenticationAgent(ADMIN_SESSION_COOKIE, []byte(sessionKey), sysdb, true, SystemWideLogger, func(w http.ResponseWriter, r *http.Request) {
		//Not logged in. Redirecting to login page
		http.Redirect(w, r, "/login.html", http.StatusTemporaryRedirect)
	})

	authAgent.LegacySessionNames = []string{LEGACY_ADMIN_SESSION_COOKIE} //dunreecompat.go
	authAgent.SetAuditFile(CONF_FOLDER + "/" + authAuditFile)
	authAgent.LoginGuard = abuseLoginGuard
	authAgent.OnLoginFailure = abuseLoginFailed

	// Create an API key manager for plugin authentication
	pluginApiKeyManager = auth.NewAPIKeyManager()

	//Create a TLS certificate manager
	tlsCertManager, err = tlscert.NewManagerWithTmp(CONF_CERT_STORE, TMP_FOLDER, SystemWideLogger)
	if err != nil {
		panic(err)
	}
	initUpstreamClientCertLoader() //client certificates for mTLS towards upstreams
	//Forget the stored ACME DNS provider / credentials when a certificate is deleted (upstream #1193)
	tlsCertManager.OnCertRemoved = func(name string) {
		for _, suffix := range []string{"_dns_provider", "_dns_credentials", "_dns_servers"} {
			if sysdb.KeyExists("acme", name+suffix) {
				sysdb.Delete("acme", name+suffix)
			}
		}
	}

	//Create a redirection rule table
	db.NewTable("redirect")
	redirectAllowRegexp := false
	db.Read("redirect", "regex", &redirectAllowRegexp)
	redirectCaseSensitive := false
	db.Read("redirect", "case_sensitive", &redirectCaseSensitive)
	redirectTable, err = redirection.NewRuleTable(CONF_REDIRECTION, redirectAllowRegexp, redirectCaseSensitive, SystemWideLogger)
	if err != nil {
		panic(err)
	}

	initRedirectAdvancedRegex()

	//Create a geodb store
	geodbStore, err = geodb.NewGeoDb(sysdb, &geodb.StoreOptions{
		AllowSlowIpv4LookUp:          !*enableHighSpeedGeoIPLookup,
		AllowSlowIpv6Lookup:          !*enableHighSpeedGeoIPLookup,
		Logger:                       SystemWideLogger,
		SlowLookupCacheClearInterval: GEODB_CACHE_CLEAR_INTERVAL * time.Minute,
		ExternalGeoDBFolder:          CONF_GEODB_PATH,
		RequesterIP:                  requesterIPForGeoDB,
	})
	if err != nil {
		panic(err)
	}

	//Create a load balancer
	loadBalancer = loadbalance.NewLoadBalancer(&loadbalance.Options{
		SystemUUID: clusterMgr.KeyMaterial(nodeUUID, cluster.PurposeStickySession),
		Geodb:      geodbStore,
		Logger:     SystemWideLogger,
	})

	//Create the access controller
	accessController, err = access.NewAccessController(&access.Options{
		Database:           sysdb,
		GeoDB:              geodbStore,
		ConfigFolder:       CONF_ACCESS_RULE,
		TrustedProxiesFile: CONF_TRUSTED_PROXIES,
		SkipPublicIPCheck:  offline.Enabled(), //no public IP lookup in offline mode
	})
	if err != nil {
		panic(err)
	}

	//Create authentication providers
	forwardAuthRouter = forward.NewAuthRouter(&forward.AuthRouterOptions{
		Address:        "",
		Logger:         SystemWideLogger,
		Database:       sysdb,
		IsTrustedProxy: accessController.IsTrustedProxy,
	})

	//Session cookie signing + at-rest encryption: the node UUID, or the cluster derived key so any HA node accepts the session
	oauth2KeyMaterial := clusterMgr.KeyMaterial(nodeUUID, cluster.PurposeOAuth2Session)
	oauth2Router = oauth2.NewOAuth2Router(&oauth2.OAuth2RouterOptions{
		Logger:     SystemWideLogger,
		Database:   sysdb,
		SystemUUID: oauth2KeyMaterial,
		SharedKey:  oauth2KeyMaterial != nodeUUID,
		InUse:      oauth2ProviderUsers,
	})

	zorxauth.DefaultConfigFolder = CONF_FOLDER + "/sso/zorxauth"
	//Opt-in (Cluster page, sharedSsoSessions in conf/cluster.json) and only with a cluster secret: the SSO portal sessions are
	//signed tokens every node accepts. Otherwise they stay random ids kept per node, also when a secret is set
	if key, ok := clusterMgr.SharedSSOSessionKey(nodeUUID); ok {
		zorxauth.SharedSessionKey = key
	}
	zorxAuthRouter = zorxauth.NewAuthRouter(sysdb, SystemWideLogger)
	zorxAuthRouter.UsersManagedElsewhere = clusterMgr.SettingsReadOnly //follower with synced users: self-service changes would be overwritten
	//The SSO portal sends its one-time session code only to hosts a proxy rule protects with ZorxAuth (nothing until the proxy router exists)
	zorxAuthRouter.SessionTargetPolicy = func(host string) (bool, bool) {
		return dynamicProxyRouter.ZorxAuthSessionTarget(host)
	}

	//Create a statistic collector
	statisticCollector, err = statistic.NewStatisticCollector(statistic.CollectorOption{
		Database:             sysdb,
		MaxEntriesPerStatMap: *statsMaxEntriesPerMap,
	})
	if err != nil {
		panic(err)
	}
	statisticCollector.SetAutoSave(STATISTIC_AUTO_SAVE_INTERVAL)
	loadStatSettings()
	initVisitors()
	initBlockLog()

	//Start the static web server
	staticWebServer = webserv.NewWebServer(&webserv.WebServerOptions{
		Sysdb:                  sysdb,
		Port:                   strconv.Itoa(WEBSERV_DEFAULT_PORT), //Default Port
		WebRoot:                *path_webserver,
		EnableDirectoryListing: true,
		EnableWebDAV:           false,  //WebDAV disabled by default, can be enabled via UI
		WebDAVPort:             "5488", //Default WebDAV port
		Logger:                 SystemWideLogger,
		AuthAgent:              authAgent,
	})
	//Restore the web server to previous shutdown state
	staticWebServer.RestorePreviousState()

	//Create a netstat buffer
	netstatBuffers, err = netstat.NewNetStatBuffer(300, SystemWideLogger)
	if err != nil {
		SystemWideLogger.PrintAndLog("Network", "Failed to load network statistic info", err)
		panic(err)
	}

	//Start the status page host resource monitors
	//CPU / RAM usage is sampled once per second in the background so the
	//dashboard API can return cached values without blocking
	shellexec.SetDockerMode(*runningInDocker) //Docker images ship sh but not bash
	usageinfo.StartBackgroundMonitor()
	hardwareinfo.SetLogger(SystemWideLogger)
	hardwareinfo.StartHostInfoCache()
	initDashboardBandwidthTracker()

	/*
		Path Rules

		This section of starutp script start the path rules where
		user can define their own routing logics
	*/

	pathRuleHandler = pathrule.NewPathRuleHandler(&pathrule.Options{
		Enabled:      false,
		ConfigFolder: CONF_PATH_RULE,
	})

	/*
		MDNS Discovery Service

		This discover nearby ArozOS Nodes or other services
		that provide mDNS discovery with domain (e.g. Synology NAS)
	*/

	if *allowMdnsScanning {
		portInt, err := strconv.Atoi(strings.Split(*webUIPort, ":")[1])
		if err != nil {
			portInt = 8000
		}

		hostName, mdnsAliases := mdnsInstanceNames(*mdnsName, nodeUUID, wirecompat.EmitLegacy())

		mdnsScanner, err = mdns.NewMDNS(mdns.NetworkHost{
			HostName:     hostName,
			Port:         portInt,
			Domain:       MDNS_IDENTIFY_DOMAIN,
			Model:        MDNS_IDENTIFY_DEVICE_TYPE,
			UUID:         nodeUUID,
			Vendor:       MDNS_IDENTIFY_VENDOR,
			BuildVersion: SYSTEM_VERSION,
		}, "")
		if err != nil {
			SystemWideLogger.Println("Unable to startup mDNS service. Disabling mDNS services")
		} else {
			for _, alias := range mdnsAliases {
				if err := mdnsScanner.RegisterAlias(alias); err != nil {
					SystemWideLogger.Println("mDNS: could not also announce " + alias + ": " + err.Error())
				}
			}
			//Start initial scanning
			go func() {
				hosts := mdnsScanner.Scan(MDNS_SCAN_TIMEOUT, "")
				previousmdnsScanResults = hosts
				SystemWideLogger.Println("mDNS Startup scan completed")
			}()

			//Create a ticker to update mDNS results every 5 minutes
			ticker := time.NewTicker(MDNS_SCAN_UPDATE_INTERVAL * time.Minute)
			stopChan := make(chan bool)
			go func() {
				for {
					select {
					case <-stopChan:
						ticker.Stop()
					case <-ticker.C:
						hosts := mdnsScanner.Scan(MDNS_SCAN_TIMEOUT, "")
						previousmdnsScanResults = hosts
						SystemWideLogger.Println("mDNS scan result updated")
					}
				}
			}()
			mdnsTickerStop = stopChan
		}
	}

	//Create WebSSH Manager
	webSshManager = sshprox.NewSSHProxyManager()
	webSshManager.KnownHostsFile = filepath.Join(CONF_FOLDER, "webssh_known_hosts")

	//Create TCP Proxy Manager
	streamProxyManager, err = streamproxy.NewStreamProxy(&streamproxy.Options{
		AccessControlHandler: accessController.DefaultAccessRule.AllowConnectionAccess,
		AccessController:     accessController,
		ConfigStore:          CONF_STREAM_PROXY,
		Logger:               SystemWideLogger,
	})
	if err != nil {
		panic(err)
	}
	//Stream targets are judged by the allowed backend list like proxy rule upstreams (no list = no check)
	streamProxyManager.TargetCheck = func(target string) error { return validateBackendTarget(target, false) }

	//Create WoL MAC storage table
	sysdb.NewTable("wolmac")

	//Create an analytic loader
	AnalyticLoader = analytic.NewDataLoader(sysdb, statisticCollector)

	//Create basic forward proxy
	sysdb.NewTable("fwdproxy")
	fwdProxyEnabled := false
	fwdProxyPort := 5587
	sysdb.Read("fwdproxy", "port", &fwdProxyPort)
	sysdb.Read("fwdproxy", "enabled", &fwdProxyEnabled)
	forwardProxy = forwardproxy.NewForwardProxy(sysdb, fwdProxyPort, SystemWideLogger)
	if fwdProxyEnabled {
		SystemWideLogger.PrintAndLog("Forward Proxy", "HTTP Forward Proxy Listening on :"+strconv.Itoa(forwardProxy.Port), nil)
		forwardProxy.Start()
	}

	/*
		ACME API

		Obtaining certificates from ACME Server
	*/
	//Create a table just to store acme related preferences
	sysdb.NewTable("acmepref")
	initCertHooks()
	initNotifyCenter() //channels, rules and event sources, see notifyevents.go
	initCertMapDir()
	acmeHandler = initACME()
	acmeAutoRenewer, err = acme.NewAutoRenewer(
		ACME_AUTORENEW_CONFIG_PATH,
		CONF_CERT_STORE,
		int64(*acmeAutoRenewInterval),
		*acmeCertAutoRenewDays,
		acmeHandler,
		SystemWideLogger,
	)
	if err != nil {
		log.Fatal(err)
	}

	/*
		Plugin Manager
	*/
	pluginFolder := *path_plugin
	pluginFolder = strings.TrimSuffix(pluginFolder, "/")

	DunreePort := 8000
	DunreeAddrPort, err := netip.ParseAddrPort(*webUIPort)

	if err != nil {
		// check for ":<port>" parameter
		webUIPortNoPrefix, hadPrefix := strings.CutPrefix(*webUIPort, ":")
		if hadPrefix {
			DunreeAddrPort, err = netip.ParseAddrPort("0.0.0.0:" + webUIPortNoPrefix)
		}
	}

	if err == nil && DunreeAddrPort.IsValid() && DunreeAddrPort.Port() > 0 {
		DunreePort = int(DunreeAddrPort.Port())
	} else {
		SystemWideLogger.PrintAndLog("plugin-manager", fmt.Sprintf("Could not set port for plugin communication (webUI/-port); fallback to default port '%d'", DunreePort), err)
	}

	if webUILoopbackListener != nil {
		//Web UI is HTTPS: plugins call back over the plain HTTP loopback-only listener
		DunreePort = webUILoopbackListener.Addr().(*net.TCPAddr).Port
	}

	pluginManager = plugins.NewPluginManager(&plugins.ManagerOptions{
		PluginDir:          pluginFolder,
		Database:           sysdb,
		Logger:             SystemWideLogger,
		PluginGroupsConfig: CONF_PLUGIN_GROUPS,
		APIKeyManager:      pluginApiKeyManager,
		RunAsUser:          *plugin_user,
		ProbePluginPorts:   *plugin_port_probe,
		RunAsGroup:         *plugin_group,
		IndexPublicKeyFile: *plugin_index_key,
		ReleasePublicKey:   releasePublicKeyBytes(), //refused as the plugin index key

		//Isolated plugin pages (opt-in, plugin safety settings): the host of the admin UI, the next port
		IsolatedUIDefaultListen: isolatedPluginUIDefaultListen(*webUIPort),
		UIListenerWrap:          pluginUIListenerWrap,
		UIHandlerWrap:           pluginUIAllowList,
		UIStaticAssets:          pluginUIStaticAssets(),

		Audit: func(event string, target string, detail map[string]string) {
			//secAudit is read when the event happens; Record of a nil logger does nothing
			secAudit.Record(secaudit.Event{Actor: "plugin manager", Event: event, Target: target, Detail: detail})
		},
		DunreePort: DunreePort,
		CSRFTokenGen: func(r *http.Request) string {
			return csrf.Token(r)
		},
		SystemConst: pluginRuntimeConst(), //dunree_* and the legacy zoraxy_* fields, see wirecompatapi.go
		/* Add-on store: no built-in source. The administrator chooses one under System > App Store
		   (mod/plugins/store_sources.go). An installation that existed before this start keeps the
		   source it synced from, written into its settings once. */
		PluginStoreURLs: nil,
		ExistingInstall: pluginStoreExistingInstall(),
		/* Developer Options */
		EnableHotReload:   *development_build, //Default to true if development build
		HotReloadInterval: 5,                  //seconds
	})

	/*
		Event Manager
	*/
	eventsystem.InitEventSystem(SystemWideLogger)

	//Sync latest plugin list from the plugin store
	go func() {
		if offline.Enabled() {
			SystemWideLogger.PrintAndLog("plugin-manager", "Offline mode: plugin store sync skipped", nil)
			return
		}
		if !pluginManager.StoreConfigured() {
			SystemWideLogger.PrintAndLog("plugin-manager", "No add-on store configured: nothing is fetched. Choose one under System > App Store", nil)
			return
		}
		err = pluginManager.UpdateDownloadablePluginList()
		if err != nil {
			SystemWideLogger.PrintAndLog("plugin-manager", "Failed to sync plugin list from plugin store", err)
		} else {
			SystemWideLogger.PrintAndLog("plugin-manager", "Plugin list synced from plugin store", nil)
		}
	}()

	err = pluginManager.LoadPluginsFromDisk()
	if err != nil {
		SystemWideLogger.PrintAndLog("plugin-manager", "Failed to load plugins", err)
	}
	pluginManager.StartIsolatedUI() //only when "isolated plugin pages" is turned on (off by default)

	/* Docker UX Optimizer */
	if runtime.GOOS == "windows" && *runningInDocker {
		SystemWideLogger.PrintAndLog("warning", "Invalid start flag combination: docker=true && runtime.GOOS == windows. Running in docker UX development mode.", nil)
	}
	DockerUXOptimizer = dockerux.NewDockerOptimizer(*runningInDocker, SystemWideLogger)

}

/* Finalize Startup Sequence */
// This sequence start after everything is initialized
func finalSequence() {
	//Start ACME renew agent
	acmeRegisterSpecialRoutingRule()

	//Inject routing rules
	registerBuildInRoutingRules()

	//Set the host specific TLS behavior resolver for resolving TLS behavior for each hostname
	tlsCertManager.SetHostSpecificTlsBehavior(dynamicProxyRouter.ResolveHostSpecificTlsBehaviorForHostname)

	//Opt-in split-horizon DNS responder (off unless enabled), see dnsresponder_glue.go
	startDNSResponder()
	initZrok()
}

/* Shutdown Sequence */

// ShutdownSeq stops Dunree in order: stop accepting and drain in-flight proxy requests (bounded by
// -shutdown_drain), then flush and close every module. Every step is bounded, see shutdown.go.
// Safe to call more than once (signal plus Fleet restart): later callers wait for the first run.
func ShutdownSeq() { runShutdownSeq(signalDrain(), shutdownStepBudget) }

// ShutdownSeqForUpdater is the updater's hook: the updater waits 20 s for it, so the drain is capped.
func ShutdownSeqForUpdater() {
	d := shutdownDrainDuration()
	if d > updaterDrainCap {
		d = updaterDrainCap
	}
	runShutdownSeq(d, shutdownStepBudget)
}

func runShutdownSeq(drain, budget time.Duration) {
	shutdownMu.Lock()
	if shutdownRunning {
		done := shutdownDone
		shutdownMu.Unlock()
		select { //a second caller never runs the steps again, and never waits unbounded
		case <-done:
		case <-time.After(drain + budget + 2*time.Second):
		}
		return
	}
	shutdownRunning = true
	shutdownDone = make(chan struct{})
	shutdownMu.Unlock()
	defer close(shutdownDone)

	SystemWideLogger.Println("Shutting down " + SYSTEM_NAME)
	//checkpoint the state that lives in files before the drain: a supervisor that kills the process while
	//requests are draining (docker stop waits 10 s) must not lose the logs, visitors and statistics
	cp := newStepRunner(checkpointBudget, shutdownLog)
	cp.limit = checkpointBudget / 2
	cp.run("checkpoint blocked request log", func() {
		if blockLog != nil {
			blockLog.Save()
		}
	})
	cp.run("checkpoint visitor list", func() {
		if visitorTracker != nil {
			visitorTracker.Save()
		}
	})
	cp.run("checkpoint statistics", func() {
		if statisticCollector != nil {
			statisticCollector.SaveSummaryOfDay()
		}
	})
	cp.run("checkpoint bandwidth counters", func() { dashboardBandwidth.save() })
	if drain > 0 && dynamicProxyRouter != nil && dynamicProxyRouter.Running {
		SystemWideLogger.Println("Closing listeners and draining in-flight requests (up to " + drain.String() + ")")
		drainProxy(dynamicProxyRouter, drain, shutdownLog)
	}

	steps := newStepRunner(budget, shutdownLog)
	steps.run("history", func() { stopHistory() })
	steps.run("live sampler", func() { stopLiveSampler() })
	steps.run("DNS responder", func() { stopDNSResponder() })
	steps.run("Netstats", func() {
		if netstatBuffers != nil {
			netstatBuffers.Close()
		}
	})
	steps.run("abuse manager", func() { stopAbuseManager() })
	steps.run("CrowdSec", func() { stopCrowdSec() })
	steps.run("ECH", func() { stopEch() })
	steps.run("zrok", func() { stopZrok() })
	steps.run("blocked request log", func() {
		if blockLog != nil {
			blockLog.Close()
		}
	})
	steps.run("visitor list", func() {
		if visitorTracker != nil {
			visitorTracker.Close()
		}
	})
	steps.run("statistics", func() {
		if statisticCollector != nil {
			statisticCollector.Close()
		}
	})
	steps.run("bandwidth counters", func() {
		if dashboardBandwidth != nil {
			dashboardBandwidth.Close()
		}
	})
	steps.run("load balancer", func() {
		if loadBalancer != nil {
			loadBalancer.Close()
		}
	})
	steps.run("certificate watcher", func() {
		if certExpiryWatcher != nil {
			certExpiryWatcher.Stop()
		}
	})
	steps.run("ACME renewer", func() {
		if acmeAutoRenewer != nil {
			acmeAutoRenewer.Close()
		}
	})
	steps.run("access controller", func() {
		if accessController != nil {
			accessController.Close()
		}
	})
	steps.run("Geo-IP database", func() {
		if geodbStore != nil {
			geodbStore.Close()
		}
	})
	steps.run("auth router", func() { //saves browser sessions
		if zorxAuthRouter != nil {
			zorxAuthRouter.Close()
		}
	})
	steps.run("plugin manager", func() {
		if pluginManager != nil {
			pluginManager.Close()
		}
	})
	steps.run("tmp files", func() { os.RemoveAll(TMP_FOLDER) })
	steps.run("system database", func() { sysdb.Close() })
	steps.run("logger", func() { SystemWideLogger.Close() })
	loggerClosed.Store(true)
	//mDNS last: its ticker can block for up to one scan, and it must not eat the budget of the steps that save state
	steps.run("mDNS", func() {
		if mdnsTickerStop != nil {
			mdnsTickerStop <- true //can block while a scan runs, hence the bound
		}
		if mdnsScanner != nil {
			mdnsScanner.Close()
		}
	})
}
