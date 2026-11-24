//go:build unix

// plugin-check is the conformance kit for Dunree plugins: it starts one plugin
// binary the way Dunree does, without Dunree, and reports whether the plugin
// keeps the plugin contract (docs/plugins/contract.md).
//
//	plugin-check [options] <plugin binary>
//
// The plugin is copied to a scratch folder and run there, on loopback ports, as
// the user who runs the kit. It is never run in its own folder and never talks to
// a real Dunree: a plugin that asks for Dunree API endpoints gets the port of a
// stand-in that records what is called. The method, every check and its limits
// are in docs/plugins/conformance.md.
//
// Exit code: 0 = no check failed (warnings are allowed), 1 = at least one check
// failed, 2 = the kit could not run.
//
// Standard library only. Build: cd tools/plugin-check && go build -o plugin-check .
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

// envList collects the -env options
type envList []string

func (e *envList) String() string     { return strings.Join(*e, " ") }
func (e *envList) Set(v string) error { *e = append(*e, v); return nil }

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	o := defaultOptions()
	fs := flag.NewFlagSet("plugin-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print the report as JSON instead of text")
	out := fs.String("out", "", "also write the JSON report to this `file`")
	ports := fs.String("ports", "", "ports the kit may use, as `first-last` (default: any free port)")
	fs.BoolVar(&o.WithFolder, "with-folder", false, "copy the whole folder of the plugin to the scratch folder, not only the program (for plugins that need files next to it; their settings are then used)")
	fs.BoolVar(&o.NoEgress, "no-egress", false, "point the HTTP proxy variables of the plugin at a dead address, so a plugin that honours them cannot call out")
	fs.BoolVar(&o.Keep, "keep", false, "keep the scratch folder")
	fs.Var((*envList)(&o.Env), "env", "environment for the plugin, as `NAME=VALUE`, or NAME to pass on the value the kit has (may be given more than once). Without it the plugin gets PATH, a HOME and TMPDIR in the scratch folder, LANG, LC_ALL, LC_CTYPE and TZ, and nothing else of the environment of the kit")
	fs.DurationVar(&o.IntrospectTimeout, "introspect-timeout", o.IntrospectTimeout, "time limit of the introspect call (Dunree: 10s)")
	fs.DurationVar(&o.ReadyTimeout, "ready-timeout", o.ReadyTimeout, "time the plugin has to open its port")
	fs.DurationVar(&o.MinRun, "min-run", o.MinRun, "the plugin has to stay up at least this long")
	fs.IntVar(&o.Calls, "calls", o.Calls, "calls made before the memory is compared")
	fs.IntVar(&o.LoadCalls, "load-calls", o.LoadCalls, "calls of the latency check")
	fs.IntVar(&o.Concurrency, "concurrency", o.Concurrency, "parallel calls of the latency check")
	fs.IntVar(&o.Events, "events", o.Events, "events sent in a row")
	fs.DurationVar(&o.MaxLatency, "max-latency", o.MaxLatency, "the latency check fails when 95 of 100 calls are not faster than this")
	fs.DurationVar(&o.WarnLatency, "warn-latency", o.WarnLatency, "the latency check warns above this")
	fs.IntVar(&o.MemCapMB, "mem-cap-mb", o.MemCapMB, "the plugin is ended when it uses more memory than this (MiB)")
	fs.IntVar(&o.MemGrowthMB, "mem-growth-mb", o.MemGrowthMB, "the memory check fails when the plugin grew by more than this over the calls (MiB)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: plugin-check [options] <plugin binary>")
		fmt.Fprintln(stderr, "Runs one Dunree plugin through the conformance checks. See docs/plugins/conformance.md.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	o.Binary = fs.Arg(0)
	if *ports != "" {
		first, last, ok := strings.Cut(*ports, "-")
		o.PortMin, _ = strconv.Atoi(first)
		o.PortMax, _ = strconv.Atoi(last)
		if !ok || o.PortMin < 1 || o.PortMax > 65535 || o.PortMax-o.PortMin < 3 {
			fmt.Fprintln(stderr, "plugin-check: -ports needs first-last with at least four ports, for example 20740-20799")
			return 2
		}
	}
	if o.Calls < 1 || o.LoadCalls < 1 || o.Concurrency < 1 || o.Concurrency > 64 || o.Events < 0 || o.MemCapMB < 16 {
		fmt.Fprintln(stderr, "plugin-check: -calls, -load-calls and -concurrency (at most 64) must be at least 1, -events at least 0, -mem-cap-mb at least 16")
		return 2
	}
	if st, err := os.Stat(o.Binary); err != nil || !st.Mode().IsRegular() {
		fmt.Fprintln(stderr, "plugin-check: not a file:", o.Binary)
		return 2
	}

	//The plugin runs in a process group of its own, so Ctrl-C in the terminal does not
	//reach it: the kit has to end it, or a program of somebody else stays on the machine.
	sig, done := make(chan os.Signal, 1), make(chan struct{})
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		select {
		case s := <-sig:
			fmt.Fprintf(stderr, "plugin-check: %s: ending the plugin and removing the scratch folder\n", s)
			abortAll()
			os.Exit(2)
		case <-done:
		}
	}()
	rep := Run(o)
	signal.Stop(sig)
	close(done)
	js, _ := json.MarshalIndent(rep, "", " ")
	if *out != "" {
		if err := os.WriteFile(*out, append(js, '\n'), 0o644); err != nil {
			fmt.Fprintln(stderr, "plugin-check: the report could not be written:", err)
			return 2
		}
	}
	if *asJSON {
		fmt.Fprintln(stdout, string(js))
	} else {
		writeText(stdout, rep)
	}
	if rep.Result != statusPass {
		return 1
	}
	return 0
}

func writeText(w io.Writer, rep *Report) {
	fmt.Fprintf(w, "%s %s, plugin contract version %d\n", rep.Tool, rep.ToolVersion, rep.Contract)
	fmt.Fprintf(w, "binary  %s\n        %d bytes, sha256 %s\n", rep.Binary, rep.Size, rep.SHA256)
	if p := rep.Plugin; p != nil {
		kind := "router"
		if p.Type == 1 {
			kind = "utility"
		}
		contract := "legacy plugin (no api_version)"
		if p.APIVersion > 0 {
			contract = "contract version " + strconv.Itoa(p.APIVersion)
		}
		fmt.Fprintf(w, "plugin  %s  %q  %s  %s, %s\n", p.ID, p.Name, p.Version, kind, contract)
	}
	fmt.Fprintln(w)
	for _, c := range rep.Checks {
		fmt.Fprintf(w, "  %-4s  %-16s %s\n", strings.ToUpper(c.Status), c.ID, c.Title)
		if c.Detail != "" {
			fmt.Fprintf(w, "        %s\n", c.Detail)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "result  %s: %d passed, %d warnings, %d failed, %d not applicable or not run\n", strings.ToUpper(rep.Result), rep.Counts[statusPass], rep.Counts[statusWarn], rep.Counts[statusFail], rep.Counts[statusSkip])
	if rep.Result != statusPass && len(rep.LogTail) > 0 {
		fmt.Fprintln(w, "\nlast output of the plugin:")
		for _, line := range rep.LogTail {
			fmt.Fprintln(w, "  | "+line)
		}
	}
}
