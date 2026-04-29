package naive

import (
	"errors"
	"fmt"
	"strings"
	"text/template"
)

// Options drives the Caddyfile render. Only fields here are
// interpolated into the template; everything else is fixed so an
// operator can't accidentally undo a stealth setting.
type Options struct {
	// Domain is the FQDN clients use. Picked up by tls automation
	// and exposed in the Host directive.
	Domain string

	// ListenPort is where forward_proxy listens. Defaults to 443.
	ListenPort int

	// Email is the ACME contact (optional). When empty, ACME is
	// still issued anonymously — Caddy supports that.
	Email string

	// Username/Password drive the basic_auth challenge that gates
	// the forward_proxy. Empty values are rejected.
	Username string
	Password string

	// ProbeResistance is the secret hostname that disables the
	// proxy's "I am a forward proxy" reply when actively probed.
	// REQUIRED — empty value means an unauthenticated probe can
	// distinguish us from a vanilla webserver.
	ProbeResistance string

	// SiteRoot is the directory served as a static fallback when
	// requests don't carry valid forward-proxy auth. Defaults to
	// [DefaultSiteRoot]. Subscriptions live under <SiteRoot>/sub/.
	SiteRoot string

	// SelfStealPort is the loopback port that serves the standalone
	// selfsteal site — the REALITY upstream destination. The port is
	// distinct from [ListenPort] so a snooper probing :SelfStealPort
	// directly never sees the forward_proxy challenge or the
	// subscription tree. Defaults to [DefaultSelfStealPort].
	SelfStealPort int

	// SelfStealRoot is the directory file_served on :SelfStealPort.
	// MUST be different from [SiteRoot] so a snooper following a
	// REALITY relay never reaches /sub/<token>/. Defaults to
	// [DefaultSelfStealRoot].
	SelfStealRoot string

	// AdminSocket overrides Caddy's admin endpoint. Empty → local
	// unix socket, "off" → admin disabled, anything else → emitted
	// verbatim.
	AdminSocket string
}

// Defaults applied by [Render] when a field is left zero.
const (
	DefaultListenPort    = 443
	DefaultSiteRoot      = "/var/lib/xray-aio/naive-selfsteal"
	DefaultSelfStealPort = 8443
	DefaultSelfStealRoot = "/var/lib/xray-aio/selfsteal"
	DefaultAdminSocket   = "unix//run/xray-aio/caddy-naive-admin.sock"
)

// caddyfileBadChars is the strict character set rejected in every
// interpolated field.
const caddyfileBadChars = " \t\r\n{};'\""

// Render returns the Caddyfile for o.
func Render(o Options) (string, error) {
	if o.ListenPort == 0 {
		o.ListenPort = DefaultListenPort
	}
	if o.SiteRoot == "" {
		o.SiteRoot = DefaultSiteRoot
	}
	if o.SelfStealPort == 0 {
		o.SelfStealPort = DefaultSelfStealPort
	}
	if o.SelfStealRoot == "" {
		o.SelfStealRoot = DefaultSelfStealRoot
	}
	if o.AdminSocket == "" {
		o.AdminSocket = DefaultAdminSocket
	}
	if err := o.validate(); err != nil {
		return "", err
	}

	tpl, err := template.New("naive").Parse(caddyfileTemplate)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}
	var sb strings.Builder
	if err := tpl.Execute(&sb, o); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}
	return sb.String(), nil
}

func (o Options) validate() error {
	if err := rejectInjection("Domain", o.Domain); err != nil {
		return err
	}
	if o.Domain == "" {
		return errors.New("Domain is required")
	}
	if o.ListenPort <= 0 || o.ListenPort > 65535 {
		return fmt.Errorf("ListenPort %d out of range", o.ListenPort)
	}
	if o.Username == "" || o.Password == "" {
		return errors.New("Username and Password are required")
	}
	if err := rejectInjection("Username", o.Username); err != nil {
		return err
	}
	if err := rejectInjection("Password", o.Password); err != nil {
		return err
	}
	// basic_auth in Caddyfile is whitespace-separated user pass —
	// even though we already reject whitespace via
	// rejectInjection, we also reject ':' so a hostile password
	// can't be confused with the URL-syntax separator some
	// clients use to encode credentials.
	if strings.ContainsAny(o.Username+o.Password, ":") {
		return errors.New("Username/Password must not contain ':'")
	}
	if o.Email != "" {
		if err := rejectInjection("Email", o.Email); err != nil {
			return err
		}
	}
	if o.ProbeResistance == "" {
		return errors.New("ProbeResistance is required (empty disables the active-probe defense)")
	}
	if err := rejectInjection("ProbeResistance", o.ProbeResistance); err != nil {
		return err
	}
	if !strings.HasPrefix(o.SiteRoot, "/") {
		return fmt.Errorf("SiteRoot must be absolute, got %q", o.SiteRoot)
	}
	if err := rejectInjection("SiteRoot", o.SiteRoot); err != nil {
		return err
	}
	if o.SelfStealPort <= 0 || o.SelfStealPort > 65535 {
		return fmt.Errorf("SelfStealPort %d out of range", o.SelfStealPort)
	}
	if o.SelfStealPort == o.ListenPort {
		return fmt.Errorf("SelfStealPort and ListenPort must differ (both %d)", o.SelfStealPort)
	}
	if !strings.HasPrefix(o.SelfStealRoot, "/") {
		return fmt.Errorf("SelfStealRoot must be absolute, got %q", o.SelfStealRoot)
	}
	if err := rejectInjection("SelfStealRoot", o.SelfStealRoot); err != nil {
		return err
	}
	if o.SelfStealRoot == o.SiteRoot {
		return fmt.Errorf("SelfStealRoot and SiteRoot must differ so a REALITY relay never reaches /sub/* (both %q)", o.SiteRoot)
	}
	if o.AdminSocket != "off" {
		if err := rejectInjection("AdminSocket", o.AdminSocket); err != nil {
			return err
		}
	}
	return nil
}

func rejectInjection(field, v string) error {
	if strings.ContainsAny(v, caddyfileBadChars) {
		return fmt.Errorf("%s contains invalid characters: %q", field, v)
	}
	return nil
}

// caddyfileTemplate produces a unified Caddy config with two HTTPS
// site-blocks sharing one ACME account and one cert store:
//
//  1. <Domain>:<ListenPort> — public NaïveProxy listener. forward_proxy
//     gated by basic_auth (with hide_ip/hide_via/probe_resistance);
//     unauthenticated requests fall through to the static site_root
//     (which is also where /sub/<token>/ subscriptions live).
//
//  2. <Domain>:<SelfStealPort> — loopback selfsteal site. Pure static
//     file_server, distinct directory; this is the destination Xray
//     REALITY relays a snooper to. Lives behind a Let's Encrypt cert
//     for <Domain> so the snooper sees a valid TLS chain.
//
// Both site addresses interpolate Domain so Caddy's automatic
// HTTPS / ACME handshake binds the LE certificate correctly. When
// Email is empty the ACME account is anonymous; we additionally emit
// `tls internal` on each site so staging deployments without a
// reachable :80 still come up with a working self-signed cert.
const caddyfileTemplate = `# Generated by xray-aio. Do not edit by hand — changes are overwritten.
{
	admin {{ .AdminSocket }}
{{- if .Email }}
	email {{ .Email }}
{{- end }}
}

{{ .Domain }}:{{ .ListenPort }} {
{{- if not .Email }}
	tls internal
{{- end }}
	forward_proxy {
		basic_auth {{ .Username }} {{ .Password }}
		hide_ip
		hide_via
		probe_resistance {{ .ProbeResistance }}
	}
	root * {{ .SiteRoot }}
	file_server
	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options nosniff
		Referrer-Policy no-referrer
	}
}

{{ .Domain }}:{{ .SelfStealPort }} {
{{- if not .Email }}
	tls internal
{{- end }}
	root * {{ .SelfStealRoot }}
	file_server
	encode zstd gzip
	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options nosniff
		Referrer-Policy no-referrer
	}
}
`
