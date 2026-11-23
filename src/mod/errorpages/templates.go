package errorpages

/*
	templates.go

	The themed built-in page (used for a class that has own text but no own HTML, and for every class
	when the theme is applied to the built-in pages) and the starter templates of the editor.
	All of them are self contained: no script, no external font or stylesheet.
*/

// BuiltinTemplate is the themed built-in page
const BuiltinTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="robots" content="noindex">
<title>{{.Status}} - {{.Title}}</title>
<style>
:root{--accent:{{.Theme.Accent}};--bg:#f4f5f7;--card:#fff;--text:#1f2328;--muted:#5b636d;--line:#d8dce1;--code:#eef0f3}
@media (prefers-color-scheme:dark){:root{--bg:#14171b;--card:#1d2126;--text:#e6e8eb;--muted:#9aa3ad;--line:#323840;--code:#262b32}}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%}
body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;line-height:1.5;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:24px 16px}
main{width:100%;max-width:560px;background:var(--card);border:1px solid var(--line);border-top:4px solid var(--accent);border-radius:12px;padding:32px 28px}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:24px;font-weight:700;font-size:1.05rem}
.brand img{max-height:40px;max-width:200px}
.status{font-size:.85rem;font-weight:700;color:var(--accent);letter-spacing:.04em}
h1{margin:.2em 0 .4em;font-size:1.7rem;line-height:1.25;overflow-wrap:anywhere}
p{margin:.5em 0;color:var(--muted);white-space:pre-line;overflow-wrap:anywhere}
dl{margin:24px 0 0;padding-top:16px;border-top:1px solid var(--line);display:grid;grid-template-columns:auto 1fr;gap:4px 16px;font-size:.85rem;color:var(--muted)}
dt{white-space:nowrap}
dd{margin:0;color:var(--text);overflow-wrap:anywhere}
code{font:600 .95em ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);padding:.15em .5em;border-radius:6px;user-select:all}
footer{margin-top:16px;font-size:.8rem;color:var(--muted);text-align:center;max-width:560px;overflow-wrap:anywhere}
</style>
</head>
<body>
<main>
{{if or .Theme.LogoURL .Theme.LogoText}}<div class="brand">{{if .Theme.LogoURL}}<img src="{{.Theme.LogoURL}}" alt="{{.Theme.LogoText}}">{{else}}<span>{{.Theme.LogoText}}</span>{{end}}</div>
{{end}}<div class="status">{{.Status}} {{.StatusText}}</div>
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
<dl>
{{if .RequestID}}<dt>Reference</dt><dd><code>{{.RequestID}}</code></dd>
{{end}}<dt>Address</dt><dd>{{.Host}}</dd>
{{if .ClientIP}}<dt>Your address</dt><dd>{{.ClientIP}}</dd>
{{end}}<dt>Time</dt><dd>{{.Time}}</dd>
</dl>
</main>
{{if .Theme.FooterText}}<footer>{{.Theme.FooterText}}</footer>
{{end}}</body>
</html>
`

// Starter is a template the editor offers to start from
type Starter struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Desc string `json:"desc"`
	HTML string `json:"html"`
}

// Starters returns the starter templates (minimal, branded, friendly)
func Starters() []Starter {
	return []Starter{
		{"minimal", "Minimal", "Status, title and message on a plain page. The smallest thing that works.", starterMinimal},
		{"branded", "Branded", "Your logo, accent colour and footer around the message, with the reference and the time.", BuiltinTemplate},
		{"friendly", "Friendly", "A large, calm page with a short explanation of what the visitor can do next.", starterFriendly},
	}
}

const starterMinimal = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Status}} {{.Title}}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:40rem;margin:15vh auto;padding:0 1rem;line-height:1.5;color:#222;background:#fff}
@media (prefers-color-scheme:dark){body{color:#e6e8eb;background:#14171b}}
h1{font-size:1.5rem}
small{opacity:.7}
</style>
</head>
<body>
<h1>{{.Status}} - {{.Title}}</h1>
<p>{{.Message}}</p>
<small>{{.Host}} &middot; {{.Time}}{{if .RequestID}} &middot; reference {{.RequestID}}{{end}}</small>
</body>
</html>
`

const starterFriendly = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Title}}</title>
<style>
:root{--accent:{{.Theme.Accent}}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;line-height:1.6;color:#1f2328;background:#fafafa}
@media (prefers-color-scheme:dark){body{color:#e6e8eb;background:#14171b}.tips{background:#1d2126}}
main{max-width:34rem;text-align:center}
.big{font-size:5rem;font-weight:800;line-height:1;color:var(--accent);margin:0}
h1{font-size:1.6rem;margin:.6em 0 .3em;overflow-wrap:anywhere}
p{margin:.4em 0;white-space:pre-line;overflow-wrap:anywhere}
.tips{margin:1.5em auto 0;padding:1em 1.25em;border-radius:12px;background:#f0f1f3;text-align:left;font-size:.95rem}
.tips ul{margin:.3em 0 0;padding-left:1.2em}
.meta{margin-top:1.5em;font-size:.8rem;opacity:.7;overflow-wrap:anywhere}
</style>
</head>
<body>
<main>
{{if .Theme.LogoText}}<p><strong>{{.Theme.LogoText}}</strong></p>{{end}}
<p class="big">{{.Status}}</p>
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
<div class="tips">What you can do
<ul>
<li>Check the address for typing mistakes.</li>
<li>Wait a minute and load the page again.</li>
{{if .RequestID}}<li>Still stuck? Send the owner of this site the reference <strong>{{.RequestID}}</strong>.</li>{{end}}
</ul>
</div>
<p class="meta">{{.Host}} &middot; {{.Time}}{{if .Theme.FooterText}} &middot; {{.Theme.FooterText}}{{end}}</p>
</main>
</body>
</html>
`
