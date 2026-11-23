// Test fixture of the conformance kit: a plugin that keeps the contract except
// that it listens on every address of the machine instead of 127.0.0.1.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-introspect" {
		fmt.Println(`{"id":"test.badbind","name":"Bad bind","author":"plugin-check tests","description":"listens on all addresses","ui_path":"/ui","type":1}`)
		return
	}
	var conf struct {
		Port int `json:"port"`
	}
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-configure=") {
			json.Unmarshal([]byte(arg[len("-configure="):]), &conf)
		}
	}
	http.HandleFunc("/ui/term", func(w http.ResponseWriter, r *http.Request) { go os.Exit(0) })
	http.HandleFunc("/ui/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "bad bind") })
	http.ListenAndServe(fmt.Sprintf(":%d", conf.Port), nil)
}
