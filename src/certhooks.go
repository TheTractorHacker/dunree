package main

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/foleyit/dunree/mod/acme"
	"github.com/foleyit/dunree/mod/notify"
	"github.com/foleyit/dunree/mod/offline"
)

/*
	certhooks.go

	Glue between the certificate subsystem and mod/notify (webhooks and the optional command hook).
	Event sources call emitCertEvent; later batches (uptime, WAF) can call notifyManager.Emit directly.
*/

var (
	notifyManager     *notify.Manager
	certExpiryWatcher *notify.ExpiryWatcher
)

// initCertHooks loads the notification config and starts the certificate expiry watcher.
func initCertHooks() {
	var err error
	notifyManager, err = notify.NewManager(filepath.Join(CONF_FOLDER, "notify.json"), *allowHookCommands, offline.Enabled,
		func(format string, args ...any) { SystemWideLogger.Println(fmt.Sprintf(format, args...)) })
	if err != nil {
		SystemWideLogger.PrintAndLog("notify", "Unable to load notification config, hooks disabled", err)
		notifyManager, _ = notify.NewManager("", *allowHookCommands, offline.Enabled, nil)
	}
	if *allowHookCommands {
		SystemWideLogger.PrintAndLog("notify", "Command hooks are ENABLED (-allow_hook_commands): an administrator can make Dunree execute a program", nil)
	}
	certExpiryWatcher = &notify.ExpiryWatcher{
		CertDir:  CONF_CERT_STORE,
		WarnDays: notifyManager.WarnDays,
		Emit:     notifyManager.Emit,
	}
	certExpiryWatcher.Start(6 * time.Hour)
}

// acmeEventBridge converts ACME handler results into notify events.
func acmeEventBridge(ev acme.CertEvent) {
	if notifyManager == nil {
		return
	}
	out := notify.Event{
		Event:   ev.Type,
		Source:  "certificate",
		Subject: ev.CertName,
		Domains: ev.Domains,
		CA:      ev.CA,
		Error:   ev.Error,
	}
	if !ev.Expiry.IsZero() {
		exp := ev.Expiry.UTC()
		out.Expiry = &exp
	}
	notifyManager.Emit(out)
}

// acmeBeforeOrderBridge announces an ACME order that is about to start (certificate.renewing, issue #178)
// and returns the lead time the issuer has to wait. Nothing is sent and the result is 0 unless a
// webhook, channel or the command hook subscribed to the event.
func acmeBeforeOrderBridge(n acme.RenewNotice) time.Duration {
	if notifyManager == nil {
		return 0
	}
	method := notify.MethodHTTP01
	if n.UseDNS {
		method = notify.MethodDNS01
	}
	return notifyManager.AnnounceRenewal(n.CertName, n.Domains, n.CA, method, n.FirstIssue)
}
