//go:build windows

package main

/*
	Windows service: registration (service install / uninstall / start / stop / status) and the
	handler that runs Dunree under the service manager. Dunree code (Foley IT). See service.go.

	As a service, Dunree
	  - works in its data folder (default %ProgramData%\Dunree), so the usual relative defaults
	    (./conf, ./sys.db, ./log, ./plugins, ./www, ./tmp) are all below it;
	  - writes what would go to the console, and crash traces, to <data folder>\log\service.log;
	  - reports "start pending" until the admin listener is bound, then "running";
	  - runs the normal stop sequence (shutdown.go) on Stop and before a system shutdown and reports
	    "stopped" when it has finished.
*/

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceStartHintMs = 30_000           // refreshed every 5 s while starting
	serviceStopHintMs  = 35_000           // the stop sequence takes at most 28 s (shutdown.go)
	serviceStopLimit   = 40 * time.Second // after this the handler reports "stopped" even if the sequence hangs
	serviceCtlWait     = 60 * time.Second // how long "service start|stop" wait for the new state

	// Only SYSTEM and the Administrators group: the folder holds the database, private keys and tokens.
	serviceDirSDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
)

func programDataDir() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0); err == nil && p != "" {
		return p
	}
	return os.Getenv("ProgramData")
}

// createPrivateDir creates dir readable by SYSTEM and Administrators only. An existing folder is
// left exactly as it is (its permissions may have been set on purpose).
func createPrivateDir(dir string) (created bool, err error) {
	if st, err := os.Stat(dir); err == nil {
		if !st.IsDir() {
			return false, fmt.Errorf("%s exists and is not a folder", dir)
		}
		return false, nil
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return false, err
		}
	}
	sd, err := windows.SecurityDescriptorFromString(serviceDirSDDL)
	if err != nil {
		return false, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return false, err
	}
	if err := windows.CreateDirectory(p, sa); err != nil {
		return false, err
	}
	return true, nil
}

func isErrno(err error, code windows.Errno) bool {
	var e windows.Errno
	return errors.As(err, &e) && e == code
}

func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Running:
		return "running"
	case svc.ContinuePending, svc.PausePending, svc.Paused:
		return "paused"
	}
	return fmt.Sprintf("state %d", s)
}

// waitState polls until the service is in the wanted state or the time is up.
func waitState(s *mgr.Service, want svc.State, limit time.Duration) (svc.Status, error) {
	deadline := time.Now().Add(limit)
	for {
		st, err := s.Query()
		if err != nil || st.State == want || time.Now().After(deadline) {
			return st, err
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func serviceControl(cmd *serviceCommand, stdout, stderr io.Writer) int {
	fail := func(what string, err error) int {
		fmt.Fprintf(stderr, "dunree service %s: %s: %v\n", cmd.Action, what, err)
		if isErrno(err, windows.ERROR_ACCESS_DENIED) {
			fmt.Fprintln(stderr, "Run this command from an elevated (Administrator) prompt.")
		}
		return serviceExitError
	}
	m, err := mgr.Connect()
	if err != nil {
		return fail("cannot reach the service manager", err)
	}
	defer m.Disconnect()

	if cmd.Action == "install" {
		return serviceInstall(m, cmd, stdout, fail)
	}

	s, err := m.OpenService(serviceName)
	if err != nil {
		if isErrno(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			fmt.Fprintln(stdout, "The Dunree service is not installed.")
			if cmd.Action == "uninstall" {
				return 0 //nothing to remove
			}
			return serviceExitNotInstalled
		}
		return fail("cannot open the service", err)
	}
	defer s.Close()

	switch cmd.Action {
	case "status":
		st, err := s.Query()
		if err != nil {
			return fail("cannot query the service", err)
		}
		line := "Dunree service: " + stateName(st.State)
		if st.ProcessId != 0 {
			line += fmt.Sprintf(" (process %d)", st.ProcessId)
		}
		fmt.Fprintln(stdout, line)
		if c, err := s.Config(); err == nil {
			fmt.Fprintln(stdout, "Command: "+c.BinaryPathName)
		}
		switch st.State {
		case svc.Running:
			return serviceExitRunning
		case svc.Stopped:
			return serviceExitStopped
		}
		return serviceExitError

	case "start":
		if err := s.Start(); err != nil {
			if isErrno(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
				fmt.Fprintln(stdout, "The Dunree service is already running.")
				return 0
			}
			return fail("cannot start the service", err)
		}
		st, err := waitState(s, svc.Running, serviceCtlWait)
		if err != nil {
			return fail("cannot query the service", err)
		}
		fmt.Fprintln(stdout, "Dunree service: "+stateName(st.State))
		if st.State != svc.Running {
			fmt.Fprintln(stdout, "It is not running yet. See log\\"+serviceLogName+" in the data folder and the Application event log (source Dunree).")
			return serviceExitError
		}
		return 0

	case "stop":
		return serviceStop(s, stdout, fail)

	case "uninstall":
		if code := serviceStop(s, stdout, fail); code != 0 {
			return code
		}
		if err := s.Delete(); err != nil {
			return fail("cannot remove the service", err)
		}
		eventlog.Remove(serviceName) //best effort
		fmt.Fprintln(stdout, "Dunree service removed. The data folder was not touched.")
		return 0
	}
	return serviceExitUsage
}

func serviceStop(s *mgr.Service, stdout io.Writer, fail func(string, error) int) int {
	st, err := s.Control(svc.Stop)
	if err != nil {
		if isErrno(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			fmt.Fprintln(stdout, "Dunree service: stopped")
			return 0
		}
		return fail("cannot stop the service", err)
	}
	if st.State != svc.Stopped {
		if st, err = waitState(s, svc.Stopped, serviceCtlWait); err != nil {
			return fail("cannot query the service", err)
		}
	}
	fmt.Fprintln(stdout, "Dunree service: "+stateName(st.State))
	if st.State != svc.Stopped {
		return serviceExitError
	}
	return 0
}

func serviceInstall(m *mgr.Mgr, cmd *serviceCommand, stdout io.Writer, fail func(string, error) int) int {
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fail("already installed", errors.New("run \"dunree service uninstall\" first to change its settings"))
	}
	exe, err := os.Executable()
	if err != nil {
		return fail("cannot find the program file", err)
	}
	if exe, err = filepath.Abs(exe); err != nil {
		return fail("cannot find the program file", err)
	}
	dir := cmd.Dir
	if dir == "" {
		dir = defaultServiceDir(programDataDir())
	}
	created, err := createPrivateDir(dir)
	if err != nil {
		return fail("cannot create the data folder "+dir, err)
	}
	start := uint32(mgr.StartAutomatic)
	if cmd.Manual {
		start = mgr.StartManual
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:  serviceDisplayName,
		Description:  serviceDescription,
		StartType:    start,
		ErrorControl: mgr.ErrorNormal,
		Dependencies: []string{"Tcpip"},
	}, serviceStartArgs(dir, cmd.Args)...)
	if err != nil {
		return fail("cannot create the service", err)
	}
	defer s.Close()
	// Restart after a crash or a failed start (5 s, 15 s, then every minute). A stop that was asked for is not a failure.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, 24*60*60); err != nil {
		fmt.Fprintln(stdout, "Note: could not set the restart-on-failure actions:", err)
	}
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil && !strings.Contains(err.Error(), "exists") {
		fmt.Fprintln(stdout, "Note: could not register the event log source:", err)
	}
	fmt.Fprintln(stdout, "Dunree service installed.")
	fmt.Fprintln(stdout, "Program:     "+exe)
	if created {
		fmt.Fprintln(stdout, "Data folder: "+dir+" (created; only SYSTEM and Administrators can read it)")
	} else {
		fmt.Fprintln(stdout, "Data folder: "+dir+" (already there; its permissions were not changed)")
	}
	fmt.Fprintln(stdout, "Log file:    "+filepath.Join(dir, "log", serviceLogName))
	fmt.Fprintln(stdout, "Start it with: dunree service start")
	return 0
}

// openServiceLog sends the standard logger, os.Stdout, os.Stderr and the crash traces of the Go
// runtime to <dir>\log\service.log (a service has no console).
func openServiceLog(dir string) (*os.File, error) {
	logDir := filepath.Join(dir, "log")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(logDir, serviceLogName)
	rotateServiceLog(path, serviceLogMaxBytes)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	os.Stdout, os.Stderr = f, f
	log.SetOutput(f)
	windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(f.Fd()))
	windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd())) //the runtime writes a panic here
	return f, nil
}

type dunreeService struct {
	ready chan struct{} // closed when the admin listener is bound
	done  chan int      // exit code of the stop sequence
	elog  *eventlog.Log
}

func (d *dunreeService) event(msg string) {
	log.Println("[service] " + msg)
	if d.elog != nil {
		d.elog.Info(1, msg)
	}
}

// Execute is called by the service manager. It starts Dunree, forwards Stop and the pre-shutdown
// notice to the normal stop sequence and returns when that sequence has finished.
func (d *dunreeService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptPreShutdown
	checkpoint := uint32(1)
	status <- svc.Status{State: svc.StartPending, CheckPoint: checkpoint, WaitHint: serviceStartHintMs}

	serviceActive = true
	go main()

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	ready := d.ready
	var forced <-chan time.Time
	stopping := false
	for {
		select {
		case <-ready:
			ready = nil
			if !stopping {
				status <- svc.Status{State: svc.Running, Accepts: accepts}
				d.event("Dunree is running")
			}
		case <-tick.C:
			if ready != nil && !stopping { //still starting: tell the service manager that we are alive
				checkpoint++
				status <- svc.Status{State: svc.StartPending, CheckPoint: checkpoint, WaitHint: serviceStartHintMs}
			}
		case code := <-d.done:
			d.event("Dunree has stopped")
			return false, uint32(code)
		case <-forced:
			d.event("The stop sequence did not finish in time; stopping now")
			return false, 1
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.PreShutdown, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: serviceStopHintMs}
				if !stopping {
					stopping = true
					forced = time.After(serviceStopLimit)
					d.event("Stop requested")
				}
				select {
				case stopRequests <- os.Interrupt: //a second request is a force quit, as a second SIGTERM is
				default:
				}
			}
		}
	}
}

// runUnderServiceManager runs Dunree as a Windows service when the process was started by the
// service manager. It returns false at once for a normal (console) start.
func runUnderServiceManager() bool {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false
	}
	dir := serviceDirFromArgs(os.Args[1:])
	if dir == "" {
		dir = defaultServiceDir(programDataDir())
	}
	elog, _ := eventlog.Open(serviceName) //nil when the source is not registered
	fatal := func(msg string) {
		log.Println("[service] " + msg)
		if elog != nil {
			elog.Error(1, msg)
		}
		os.Exit(1)
	}
	if _, err := createPrivateDir(dir); err != nil {
		fatal("Cannot create the data folder " + dir + ": " + err.Error())
	}
	if err := os.Chdir(dir); err != nil {
		fatal("Cannot use the data folder " + dir + ": " + err.Error())
	}
	if _, err := openServiceLog(dir); err != nil {
		fatal("Cannot open the log file in " + dir + ": " + err.Error())
	}
	log.Println("[service] Starting " + serviceName + " as a Windows service, data folder " + dir)

	d := &dunreeService{ready: make(chan struct{}), done: make(chan int, 1), elog: elog}
	serviceReadyHook = func() {
		select {
		case <-d.ready:
		default:
			close(d.ready)
		}
	}
	// The stop sequence ends with exitProcess: hand the code to the handler, which reports
	// "stopped" to the service manager, and let runUnderServiceManager end the process.
	exitProcess = func(code int) {
		select {
		case d.done <- code:
		default:
		}
		select {}
	}
	if err := svc.Run(serviceName, d); err != nil {
		fatal("Service failed: " + err.Error())
	}
	if elog != nil {
		elog.Close()
	}
	os.Exit(0)
	return true
}
