package subscribe

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
)

// Bundle is the set of per-client connection blobs the subscription
// page presents in one place. Any combination of fields may be
// empty — only the populated transports are rendered.
type Bundle struct {
	Label         string // shown in <title> and the H1, e.g. "xray-aio"
	VLESSURIs     []string
	NaiveURIs     []string
	Hysteria2URIs []string
	GeneratedAt   string // RFC 3339 timestamp, optional
}

// RenderPlainText returns the subscription body in the format
// understood by clients that fetch <subscribe-url>?plain=1 — one URI
// per line. Mainstream clients (NekoBox, Hiddify, Happ) accept this
// shape directly.
func RenderPlainText(b Bundle) (string, error) {
	if len(b.VLESSURIs)+len(b.NaiveURIs)+len(b.Hysteria2URIs) == 0 {
		return "", errors.New("Bundle has no URIs")
	}
	var sb bytes.Buffer
	for _, u := range b.VLESSURIs {
		sb.WriteString(u)
		sb.WriteByte('\n')
	}
	for _, u := range b.NaiveURIs {
		sb.WriteString(u)
		sb.WriteByte('\n')
	}
	for _, u := range b.Hysteria2URIs {
		sb.WriteString(u)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// RenderHTML returns a small landing page that lists the URIs, lets
// the user copy them, and offers one-click "Add to client" links via
// custom-scheme handlers (happ://, nekobox://, etc).
//
// URIs land in two contexts:
//
//   - inside <code> nodes (HTML text context) — escaped normally
//     by html/template;
//   - inside href="…" attributes — passed through the safeURL
//     funcmap helper that returns [template.URL]. This is necessary
//     because html/template's default URL sanitizer rewrites any
//     scheme outside http/https/mailto/ftp to '#ZgotmplZ', which
//     would break the deep-links.
//
// safeURL is only ever applied to URIs the [Bundle] already validated
// by construction (built by [VLESSURI]/[NaiveURI]), so the lifted
// sanitization does not introduce a vulnerability.
func RenderHTML(b Bundle) (string, error) {
	if b.Label == "" {
		b.Label = "xray-aio"
	}
	tpl, err := template.New("page").Funcs(template.FuncMap{
		"safeURL": func(s string) template.URL { return template.URL(s) },
	}).Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	var sb bytes.Buffer
	if err := tpl.Execute(&sb, b); err != nil {
		return "", fmt.Errorf("execute: %w", err)
	}
	return sb.String(), nil
}

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{.Label}} subscription</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; max-width: 42rem; margin: 4rem auto; padding: 0 1.5rem; line-height: 1.5; }
  h1 { font-size: 1.4rem; }
  h2 { font-size: 1.05rem; margin-top: 2rem; }
  ol { padding-left: 1.25rem; }
  li { margin: .9rem 0; }
  code { font-family: ui-monospace, Menlo, Consolas, monospace; word-break: break-all; padding: .15rem .35rem; border-radius: .25rem; background: rgba(127,127,127,.12); }
  .row { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; margin-top: .25rem; }
  a.btn { display: inline-block; padding: .35rem .75rem; border: 1px solid currentColor; border-radius: .35rem; text-decoration: none; font-size: .85rem; }
  .meta { color: #666; font-size: .8rem; }
  @media (prefers-color-scheme: dark) {
    body { background: #111; color: #ddd; }
    .meta { color: #999; }
  }
</style>
</head>
<body>
<h1>{{.Label}} subscription</h1>
<p class="meta">
  Use the URIs below in your client (NekoBox, Hiddify, Streisand, Happ).
  Treat this page as a credential — anyone who sees it can connect.
</p>
{{- if .VLESSURIs}}
<h2>VLESS REALITY</h2>
<ol>
{{range $i, $u := .VLESSURIs}}
  <li>
    <code>{{$u}}</code>
    <div class="row">
      <a class="btn" href="{{safeURL $u}}">Open in default client</a>
      <a class="btn" href="{{printf "happ://add/%s" $u | safeURL}}">Add to Happ</a>
    </div>
  </li>
{{end}}
</ol>
{{- end}}
{{- if .NaiveURIs}}
<h2>NaïveProxy</h2>
<ol>
{{range $i, $u := .NaiveURIs}}
  <li>
    <code>{{$u}}</code>
    <div class="row">
      <a class="btn" href="{{safeURL $u}}">Open in default client</a>
    </div>
  </li>
{{end}}
</ol>
{{- end}}
{{- if .Hysteria2URIs}}
<h2>Hysteria 2</h2>
<ol>
{{range $i, $u := .Hysteria2URIs}}
  <li>
    <code>{{$u}}</code>
    <div class="row">
      <a class="btn" href="{{safeURL $u}}">Open in default client</a>
    </div>
  </li>
{{end}}
</ol>
{{- end}}
{{- if .GeneratedAt}}
<p class="meta">Generated: {{.GeneratedAt}}</p>
{{- end}}
</body>
</html>
`
