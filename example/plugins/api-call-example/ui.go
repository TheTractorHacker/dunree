package main

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httputil"
	"strconv"

	plugin "example.com/dunree/api-call-example/mod/dunree_plugin"
)

// callWithKey makes a GET call to Dunree with the API key of this plugin.
//
// cfg.DoAPIRequest (SDK 1.2.0) builds the address from the port Dunree handed over
// and sets the "Authorization: Bearer <api key>" header, so the key is not
// handled here at all. It does not follow redirects and gives up after 30 seconds.
func callWithKey(cfg *plugin.ConfigureSpec, endpoint string) (string, int, error) {
	resp, err := cfg.DoAPIRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", 0, fmt.Errorf("error making API call: %v", err)
	}
	defer resp.Body.Close()

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("error dumping response: %v", err)
	}
	return string(respDump), resp.StatusCode, nil
}

func allowedEndpoint(cfg *plugin.ConfigureSpec) (string, error) {
	// Make an API call to the permitted endpoint
	respDump, status, err := callWithKey(cfg, "/plugin/api/access/list")
	if err != nil {
		return respDump, err
	}

	// Check if the response status is OK
	if status != http.StatusOK {
		return respDump, fmt.Errorf("received non-OK response status %d", status)
	}

	return respDump, nil
}

func allowedEndpointInvalidKey(cfg *plugin.ConfigureSpec) (string, error) {
	// Make an API call to the permitted endpoint with an invalid key.
	// cfg.NewAPIRequest builds the same request as above without sending it; the
	// header it set is then replaced by hand to show what Dunree answers.
	req, err := cfg.NewAPIRequest(http.MethodGet, "/plugin/api/access/list", nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	// Use an invalid API key
	req.Header.Set("Authorization", "Bearer invalid-key")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making API call: %v", err)
	}
	defer resp.Body.Close()

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {

		return "", fmt.Errorf("error dumping response: %v", err)
	}

	return string(respDump), nil
}

func unaccessibleEndpoint(cfg *plugin.ConfigureSpec) (string, error) {
	// Make an API call to an endpoint that is not permitted
	respDump, _, err := callWithKey(cfg, "/api/acme/listExpiredDomains")
	return respDump, err
}

func unpermittedEndpoint(cfg *plugin.ConfigureSpec) (string, error) {
	// Make an API call to an endpoint that is plugin-accessible but is not permitted
	respDump, _, err := callWithKey(cfg, "/plugin/api/proxy/list")
	return respDump, err
}

func RenderUI(config *plugin.ConfigureSpec, w http.ResponseWriter, r *http.Request) {
	// make several types of API calls to demonstrate the plugin functionality
	accessList, err := allowedEndpoint(config)
	var RenderedAccessListHTML string
	if err != nil {
		if accessList != "" {
			RenderedAccessListHTML = fmt.Sprintf("<p>Error fetching access list: %v</p><pre>%s</pre>", err, html.EscapeString(accessList))
		} else {
			RenderedAccessListHTML = fmt.Sprintf("<p>Error fetching access list: %v</p>", err)
		}
	} else {
		// Render the access list as HTML
		RenderedAccessListHTML = fmt.Sprintf("<pre>%s</pre>", html.EscapeString(accessList))
	}

	// Make an API call with an invalid key
	invalidKeyResponse, err := allowedEndpointInvalidKey(config)
	var RenderedInvalidKeyResponseHTML string
	if err != nil {
		RenderedInvalidKeyResponseHTML = fmt.Sprintf("<p>Error with invalid key: %v</p>", err)
	} else {
		// Render the invalid key response as HTML
		RenderedInvalidKeyResponseHTML = fmt.Sprintf("<pre>%s</pre>", html.EscapeString(invalidKeyResponse))
	}

	// Make an API call to an endpoint that is not plugin-accessible
	unaccessibleResponse, err := unaccessibleEndpoint(config)
	var RenderedUnaccessibleResponseHTML string
	if err != nil {
		RenderedUnaccessibleResponseHTML = fmt.Sprintf("<p>Error with unaccessible endpoint: %v</p>", err)
	} else {
		// Render the unaccessible response as HTML
		RenderedUnaccessibleResponseHTML = fmt.Sprintf("<pre>%s</pre>", html.EscapeString(unaccessibleResponse))
	}

	// Make an API call to an endpoint that is plugin-accessible but is not permitted
	unpermittedResponse, err := unpermittedEndpoint(config)
	var RenderedUnpermittedResponseHTML string
	if err != nil {
		RenderedUnpermittedResponseHTML = fmt.Sprintf("<p>Error with unpermitted endpoint: %v</p>", err)
	} else {
		// Render the unpermitted response as HTML
		RenderedUnpermittedResponseHTML = fmt.Sprintf("<pre>%s</pre>", html.EscapeString(unpermittedResponse))
	}

	// Render the UI for the plugin
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>API Call Example Plugin UI</title>
		<meta charset="UTF-8">
		<link rel="stylesheet" href="/script/semantic/semantic.min.css">
		<script src="/script/jquery-3.6.0.min.js"></script>
		<script src="/script/semantic/semantic.min.js"></script>
		<link rel="stylesheet" href="/main.css">
		<style>
			body {
				background: none;
			}

			.response-block {
				background-color: var(--theme_bg_primary);
				border: 1px solid var(--theme_divider);
				border-radius: 8px;
				padding: 20px;
				margin: 15px 0;
				box-shadow: 0 2px 4px rgba(0,0,0,0.1);
				transition: box-shadow 0.3s ease;
			}
			.response-block:hover {
				box-shadow: 0 4px 8px rgba(0,0,0,0.15);
			}
			.response-block h3 {
				margin-top: 0;
				color: var(--text_color);
				border-bottom: 2px solid #007bff;
				padding-bottom: 8px;
			}
			.response-block.success {
				border-left: 4px solid #28a745;
			}
			.response-block.error {
				border-left: 4px solid #dc3545;
			}
			.response-block.warning {
				border-left: 4px solid #ffc107;
			}
			.response-content {
				margin-top: 10px;
			}
			.response-content pre {
				background-color: var(--theme_highlight);
				border: 1px solid var(--theme_divider);
				border-radius: 4px;
				padding: 10px;
				overflow: auto;
				font-size: 12px;
				line-height: 1.4;
				height: 200px;
				max-height: 80vh;
				min-height: 100px;
				resize: vertical;
				box-sizing: border-box;
			}
		</style>
	</head>
	<body>
	<!-- Dark theme script must be included after body tag-->
	<link rel="stylesheet" href="/darktheme.css">
	<script src="/script/darktheme.js"></script>
	<div class="ui container">

		<div class="ui basic segment">
			<h1 class="ui header">Welcome to the API Call Example Plugin UI</h1>
			<p>Plugin is running on port: ` + strconv.Itoa(config.Port) + `</p>
		</div>
		<div class="ui divider"></div>

		<h2>API Call Examples</h2>

		<div class="response-block success">
			<h3>✅ Allowed Endpoint (Valid API Key)</h3>
			<p>Making a GET request to <code>/plugin/api/access/list</code> with a valid API key:</p>
			<div class="response-content">
				` + RenderedAccessListHTML + `
			</div>
		</div>

		<div class="response-block warning">
			<h3>⚠️ Invalid API Key</h3>
			<p>Making a GET request to <code>/plugin/api/access/list</code> with an invalid API key:</p>
			<div class="response-content">
				` + RenderedInvalidKeyResponseHTML + `
			</div>
		</div>

		<div class="response-block warning">
			<h3>⚠️ Unpermitted Endpoint</h3>
			<p>Making a GET request to <code>/plugin/api/proxy/list</code> (not a permitted endpoint):</p>
			<div class="response-content">
				` + RenderedUnpermittedResponseHTML + `
			</div>
		</div>

		<div class="response-block error">
			<h3>❌ Disallowed Endpoint</h3>
			<p>Making a GET request to <code>/api/acme/listExpiredDomains</code> (not a plugin-accessible endpoint):</p>
			<div class="response-content">
				` + RenderedUnaccessibleResponseHTML + `
			</div>
		</div>
	</div>
	</body>
	</html>`
	w.Write([]byte(html))
}
