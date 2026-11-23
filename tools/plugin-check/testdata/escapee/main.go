// Test fixture of the conformance kit: a plugin that keeps the contract and
// starts a helper that leaves its process group, so the helper outlives a stop
// of the group. ESCAPEE_MODE=double: the helper is started by a process that
// ends at once, so it has no parent in the plugin any more (a daemon).
// It also prints what it sees of the environment of the kit.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func spawn(arg string) {
	cmd := exec.Command(os.Args[0], arg)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Println("escapee: helper not started:", err)
	}
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-introspect":
			fmt.Println(`{"id":"test.escapee","name":"Escapee","author":"plugin-check tests","description":"starts a helper outside its process group","ui_path":"/ui","type":1}`)
			return
		case "-escapee-linger":
			time.Sleep(90 * time.Second)
			return
		case "-escapee-fork":
			spawn("-escapee-linger")
			return
		}
	}
	var conf struct {
		Port int `json:"port"`
	}
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-configure=") {
			json.Unmarshal([]byte(arg[len("-configure="):]), &conf)
		}
	}
	fmt.Printf("escapee: secret=%t home=%s mode=%s\n", os.Getenv("PLUGIN_CHECK_TEST_SECRET") != "", os.Getenv("HOME"), os.Getenv("ESCAPEE_MODE"))
	switch os.Getenv("ESCAPEE_MODE") {
	case "none":
	case "double":
		spawn("-escapee-fork")
	default:
		spawn("-escapee-linger")
	}
	http.HandleFunc("/ui/term", func(w http.ResponseWriter, r *http.Request) { go os.Exit(0) })
	http.HandleFunc("/ui/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "escapee") })
	http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", conf.Port), nil)
}
