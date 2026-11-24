package main

/*
	Windows service support ("dunree.exe service install|uninstall|start|stop|status").

	This file is Dunree code (Foley IT); it is not part of the code Dunree is based on. It holds
	everything that does not need the Windows API, so it is tested on every
	platform: the command line of the "service" subcommand, the default data
	folder and the arguments the service is registered with. The Windows side
	is in service_windows.go; other platforms get a stub (service_other.go)
	that points to the unit files in packaging/.

	Nothing here runs unless the first argument is the word "service" or, on
	Windows, the process was started by the service manager.
*/

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	serviceName        = "Dunree"
	serviceDisplayName = "Dunree"
	serviceDescription = "Dunree reverse proxy and web gateway"
	serviceDirName     = "Dunree"      // folder below %ProgramData%
	serviceLogName     = "service.log" // in <data folder>\log: start-up messages, the standard output and crash traces
	serviceLogMaxBytes = 10 << 20      // the file is moved to service.log.1 at start when it is larger
)

// Exit codes of "service status" (the first three follow the LSB convention).
const (
	serviceExitRunning      = 0
	serviceExitError        = 1
	serviceExitUsage        = 2
	serviceExitStopped      = 3
	serviceExitNotInstalled = 4
)

var (
	// serviceDirFlag is set by "service install" in the registered command line. It is defined on every
	// platform so that a command line is valid everywhere; it only has an effect under the Windows service manager.
	serviceDirFlag = flag.String("service_dir", "", "Windows service only: data folder the service works in (conf, sys.db, log, plugins). Set by \"service install --dir\". Default: %ProgramData%\\Dunree")

	// stopRequests is the channel the stop sequence waits on (SetupCloseHandler). SIGINT / SIGTERM are
	// delivered to it; the Windows service handler sends to it when the service manager asks for a stop.
	stopRequests = make(chan os.Signal, 2)

	// exitProcess ends the process after the stop sequence. Under the Windows service manager it is
	// replaced so that the service reports "stopped" before the process exits.
	exitProcess = os.Exit

	// serviceReadyHook is called once the admin listener is bound (nil unless running as a Windows service).
	serviceReadyHook func()

	// serviceActive is true while main() runs inside the Windows service handler.
	serviceActive bool
)

// notifyStopSignals subscribes c to SIGINT / SIGTERM, except inside a Windows service. There the Go
// runtime turns CTRL_LOGOFF_EVENT, which Windows sends to every service whenever any user logs off,
// into SIGTERM once a SIGTERM handler is registered: the service would run its stop sequence, report
// a clean "stopped" and not be restarted. A service is stopped through the service manager only
// (Execute sends to stopRequests); without a Go handler the logoff event goes to the Windows
// default handler, which leaves a service running.
func notifyStopSignals(c chan<- os.Signal, notify func(chan<- os.Signal, ...os.Signal)) {
	if serviceActive {
		return
	}
	notify(c, stopSignals...)
}

// serviceReady tells the service manager that the start has finished. No-op outside a Windows service.
func serviceReady() {
	if serviceReadyHook != nil {
		serviceReadyHook()
	}
}

// serviceCommand is a parsed "service ..." command line.
type serviceCommand struct {
	Action string   // install, uninstall, start, stop, status
	Dir    string   // install: data folder ("" = default)
	Manual bool     // install: start type "manual" instead of "automatic"
	Args   []string // install: Dunree flags the service is started with
}

const serviceUsage = `Usage:
  dunree service install [--dir FOLDER] [--manual] [-- FLAG=VALUE ...]
  dunree service uninstall
  dunree service start
  dunree service stop
  dunree service status

install    registers the Windows service "Dunree" (start type automatic, restart on failure).
           --dir FOLDER   data folder for conf, sys.db, log and plugins (default %ProgramData%\Dunree)
           --manual       do not start with Windows
           Flags after "--" are passed to Dunree at every start, for example: -- -port=:8000 -webui_tls=auto
uninstall  stops and removes the service. The data folder is kept.
status     exit code 0 = running, 3 = stopped, 4 = not installed.

Run from an elevated (Administrator) prompt.
`

// parseServiceCommand parses what follows the word "service". known reports whether a Dunree flag
// exists and whether it is a boolean (nil = the flags of this program).
func parseServiceCommand(args []string, known func(name string) (exists, isBool bool)) (*serviceCommand, error) {
	if known == nil {
		known = knownFlag
	}
	if len(args) == 0 {
		return nil, errors.New("missing action")
	}
	cmd := &serviceCommand{Action: strings.ToLower(args[0])}
	rest := args[1:]
	switch cmd.Action {
	case "install":
	case "uninstall", "start", "stop", "status":
		if len(rest) != 0 {
			return nil, fmt.Errorf("%q takes no arguments", cmd.Action)
		}
		return cmd, nil
	default:
		return nil, fmt.Errorf("unknown action %q", args[0])
	}
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--":
			pass, err := checkServiceFlags(rest[i+1:], known)
			if err != nil {
				return nil, err
			}
			cmd.Args = pass
			return cmd, nil
		case a == "--manual" || a == "-manual":
			cmd.Manual = true
		case a == "--dir" || a == "-dir":
			if i+1 >= len(rest) {
				return nil, errors.New("--dir needs a folder")
			}
			i++
			cmd.Dir = rest[i]
		case strings.HasPrefix(a, "--dir=") || strings.HasPrefix(a, "-dir="):
			cmd.Dir = a[strings.Index(a, "=")+1:]
		default:
			return nil, fmt.Errorf("unknown option %q (Dunree flags go after \"--\")", a)
		}
	}
	if cmd.Dir != "" && !filepath.IsAbs(cmd.Dir) {
		return nil, fmt.Errorf("--dir must be an absolute path, got %q", cmd.Dir)
	}
	return cmd, nil
}

// checkServiceFlags refuses anything the service could not start with: an unknown flag would make
// every start fail with only a line in service.log to explain it.
func checkServiceFlags(args []string, known func(string) (bool, bool)) ([]string, error) {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") || a == "-" || a == "--" {
			return nil, fmt.Errorf("%q is not a flag: write every flag as -name=value", a)
		}
		name := strings.TrimLeft(a, "-")
		hasValue := false
		if i := strings.Index(name, "="); i >= 0 {
			name, hasValue = name[:i], true
		}
		exists, isBool := known(name)
		switch {
		case !exists:
			return nil, fmt.Errorf("unknown Dunree flag -%s (see dunree -h)", name)
		case name == "service_dir":
			return nil, errors.New("use --dir before \"--\" instead of -service_dir")
		case name == "version" || name == "doctor" || name == "reset_ac" || name == "compact-db" || name == "update_geoip" || name == "updater_watchdog" || name == "cluster_gen_secret":
			return nil, fmt.Errorf("-%s makes Dunree exit at once and cannot be a service flag", name)
		case !hasValue && !isBool:
			return nil, fmt.Errorf("-%s needs a value: write -%s=value", name, name)
		}
	}
	return append([]string(nil), args...), nil
}

func knownFlag(name string) (exists, isBool bool) {
	f := flag.Lookup(name)
	if f == nil {
		return false, false
	}
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return true, ok && b.IsBoolFlag()
}

// defaultServiceDir returns the data folder of the service: <ProgramData>\Dunree.
func defaultServiceDir(programData string) string {
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return strings.TrimRight(programData, `\/`) + `\` + serviceDirName
}

// serviceStartArgs returns the arguments the service is registered with. The data folder always
// comes first and is always explicit, so "service status" and a later reader of the registry see it.
func serviceStartArgs(dir string, pass []string) []string {
	return append([]string{"-service_dir=" + dir}, pass...)
}

// serviceDirFromArgs finds -service_dir in a command line without parsing the other flags (the
// service has to change folder and open its log before flag.Parse runs). Like the flag package,
// the last one wins and parsing stops at "--" or the first argument that is not a flag.
func serviceDirFromArgs(args []string) string {
	dir := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" || !strings.HasPrefix(a, "-") {
			break
		}
		name := strings.TrimLeft(a, "-")
		if v, ok := strings.CutPrefix(name, "service_dir="); ok {
			dir = v
		} else if name == "service_dir" && i+1 < len(args) {
			i++
			dir = args[i]
		}
	}
	return dir
}

// rotateServiceLog moves an oversized service.log aside (one generation is kept).
func rotateServiceLog(path string, maxBytes int64) error {
	st, err := os.Stat(path)
	if err != nil || st.Size() <= maxBytes {
		return nil
	}
	os.Remove(path + ".1")
	return os.Rename(path, path+".1")
}

// runServiceCommand runs "dunree service ..." and returns the exit code.
func runServiceCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(stdout, serviceUsage)
		return 0
	}
	cmd, err := parseServiceCommand(args, nil)
	if err != nil {
		fmt.Fprintln(stderr, "dunree service:", err)
		fmt.Fprint(stderr, serviceUsage)
		return serviceExitUsage
	}
	return serviceControl(cmd, stdout, stderr)
}

// serviceEntry is the first thing main() does. It returns true when there is nothing left for
// main() to do: the process was a Windows service and that service has ended. The "service"
// subcommand does not return at all.
func serviceEntry() bool {
	if serviceActive {
		return false //main() called by the service handler
	}
	if len(os.Args) > 1 && os.Args[1] == "service" {
		os.Exit(runServiceCommand(os.Args[2:], os.Stdout, os.Stderr))
	}
	return runUnderServiceManager()
}
