// Command xray-aio orchestrates installation of bypass transports (Xray,
// sing-box, NaïveProxy, Hysteria2, AmneziaWG, MTProto FakeTLS, Cloudflare
// Tunnel/Worker) on a single VPS.
//
// Phase 0 ships the CLI skeleton only; subcommands print "not implemented
// yet" and return without side-effects.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/vmhlov/xray-aio/internal/log"
	"github.com/vmhlov/xray-aio/internal/orchestrator"
	"github.com/vmhlov/xray-aio/internal/preflight"
	"github.com/vmhlov/xray-aio/internal/version"

	// Side-effect imports: each package's init() registers its
	// transport in the global transport registry.
	_ "github.com/vmhlov/xray-aio/internal/transport/amneziawg"
	_ "github.com/vmhlov/xray-aio/internal/transport/hysteria2"
	_ "github.com/vmhlov/xray-aio/internal/transport/naive"
	_ "github.com/vmhlov/xray-aio/internal/transport/xray"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	root := newRootCmd()
	if err := root.ExecuteContext(ctx); err != nil {
		log.L().Error("command failed", "err", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "xray-aio",
		Short:         "All-in-one bypass-transport orchestrator",
		Long:          `xray-aio installs and manages a stack of bypass transports (Xray, sing-box, NaïveProxy, Hysteria2, AmneziaWG, MTProto FakeTLS, Cloudflare Tunnel/Worker) on a single VPS.`,
		Version:       fmt.Sprintf("%s (%s, %s)", version.Version, version.Commit, version.Date),
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(
		newInstallCmd(),
		newStatusCmd(),
		newUpdateCmd(),
		newRotateCmd(),
		newUninstallCmd(),
		newPreflightCmd(),
	)
	return root
}

func newInstallCmd() *cobra.Command {
	opts := orchestrator.InstallOptions{}
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install one of the predefined profiles on this host",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.Domain == "" {
				return fmt.Errorf("--domain is required")
			}
			log.L().Info("install requested", "profile", opts.Profile, "domain", opts.Domain)
			res, err := orchestrator.Install(cmd.Context(), opts, orchestrator.Deps{})
			if err != nil {
				return err
			}
			printInstallResult(cmd.OutOrStdout(), res)
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.Profile, "profile", "home-stealth", "preset profile (home-stealth, home-mobile, home-vpn, home-vpn-mobile)")
	cmd.Flags().StringVar(&opts.Domain, "domain", "", "domain name clients use to reach this host (required)")
	cmd.Flags().StringVar(&opts.Email, "email", "", "email for Let's Encrypt registration (recommended)")
	cmd.Flags().IntVar(&opts.XrayPort, "xray-port", 0, "override Xray REALITY listen port (default 443)")
	cmd.Flags().IntVar(&opts.NaivePort, "naive-port", 0, "override Naive listen port (default 8444)")
	cmd.Flags().StringVar(&opts.XrayDest, "xray-dest", "", "override REALITY upstream destination (default 127.0.0.1:<naive-selfsteal-port>)")
	cmd.Flags().StringVar(&opts.NaiveSiteRoot, "naive-site-root", "", "override Naive Caddy file_server root (subscriptions land under <root>/sub/<token>/)")
	cmd.Flags().IntVar(&opts.NaiveSelfStealPort, "naive-selfsteal-port", 0, "override loopback selfsteal port served by the unified Caddy (default 8443; REALITY upstream)")
	cmd.Flags().StringVar(&opts.NaiveSelfStealRoot, "naive-selfsteal-root", "", "override directory file_served on the selfsteal port (default /var/lib/xray-aio/selfsteal)")
	cmd.Flags().IntVar(&opts.Hysteria2Port, "hysteria2-port", 0, "override Hysteria 2 UDP listen port for the home-mobile profile (default 443)")
	cmd.Flags().StringVar(&opts.Hysteria2MasqueradeURL, "hysteria2-masquerade", "", "override Hysteria 2 masquerade upstream URL (default https://127.0.0.1:<naive-selfsteal-port>)")
	cmd.Flags().IntVar(&opts.AmneziaWGListenPort, "amneziawg-listen-port", 0, "override AmneziaWG UDP listen port for the home-vpn profile (default 51842)")
	cmd.Flags().StringVar(&opts.AmneziaWGServerAddress, "amneziawg-server-address", "", "override AmneziaWG server-side TUN CIDR (default 10.66.66.1/24)")
	cmd.Flags().StringVar(&opts.AmneziaWGPeerAddress, "amneziawg-peer-address", "", "override AmneziaWG peer-side TUN CIDR (default 10.66.66.2/32)")
	cmd.Flags().IntVar(&opts.AmneziaWGMTU, "amneziawg-mtu", 0, "override AmneziaWG peer-side MTU (default 1380)")
	cmd.Flags().StringVar(&opts.AmneziaWGDNS, "amneziawg-dns", "", "override AmneziaWG peer-side DNS server (default 1.1.1.1)")
	cmd.Flags().BoolVar(&opts.SkipPreflightOnError, "skip-preflight-errors", false, "proceed even if preflight reports errors (advanced)")
	return cmd
}

func printInstallResult(w io.Writer, r *orchestrator.InstallResult) {
	if r == nil {
		return
	}
	if r.State != nil {
		fmt.Fprintf(w, "profile: %s\n", r.State.Profile)
		fmt.Fprintf(w, "domain:  %s\n", r.State.Domain)
	}
	if r.SubscriptionURL != "" {
		fmt.Fprintf(w, "\nsubscription URL (give to client):\n  %s\n", r.SubscriptionURL)
	}
	if r.BundleDir != "" {
		fmt.Fprintf(w, "bundle written: %s\n", r.BundleDir)
	}
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show installed transports and their health",
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := orchestrator.Status(cmd.Context(), orchestrator.Deps{})
			if err != nil {
				return err
			}
			printStatusReport(cmd.OutOrStdout(), r)
			return nil
		},
	}
}

func printStatusReport(w io.Writer, r *orchestrator.StatusReport) {
	if r == nil {
		return
	}
	fmt.Fprintf(w, "profile: %s\n", r.Profile)
	fmt.Fprintf(w, "domain:  %s\n", r.Domain)
	if r.SubscriptionURL != "" {
		fmt.Fprintf(w, "sub URL: %s\n", r.SubscriptionURL)
	}
	fmt.Fprintln(w)
	for _, t := range r.Transports {
		fmt.Fprintf(w, "  %-8s  running=%t  probe=%t", t.Name, t.Status.Running, t.Probe.OK)
		if t.StatErr != nil {
			fmt.Fprintf(w, "  status_err=%v", t.StatErr)
		}
		if t.ProbeErr != nil {
			fmt.Fprintf(w, "  probe_err=%v", t.ProbeErr)
		} else if t.Probe.Notes != "" {
			fmt.Fprintf(w, "  notes=%q", t.Probe.Notes)
		}
		fmt.Fprintln(w)
	}
}

func newUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update installed transport binaries to pinned versions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "update: not implemented yet (Phase 0 skeleton)")
			return nil
		},
	}
}

func newRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Rotate UUIDs/keys/paths and regenerate subscription URLs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "rotate: not implemented yet (Phase 0 skeleton)")
			return nil
		},
	}
}

func newUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove all xray-aio-installed services and configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "uninstall: not implemented yet (Phase 0 skeleton)")
			return nil
		},
	}
}

func newPreflightCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "preflight",
		Short: "Run environment checks and print results",
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, _ := preflight.Run(cmd.Context())
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "host: %s/%s\n", r.OS, r.Arch)
			for _, c := range r.Checks {
				fmt.Fprintf(out, "  %-7s  %-16s  %s\n", labelFor(c.Status), c.Name, c.Message)
			}
			if r.HasErrors() {
				return fmt.Errorf("preflight failed (%d errors, %d warnings)", countStatus(r, preflight.StatusError), countStatus(r, preflight.StatusWarn))
			}
			if r.HasWarnings() {
				fmt.Fprintf(out, "\npreflight ok (%d warnings)\n", countStatus(r, preflight.StatusWarn))
			} else {
				fmt.Fprintln(out, "\npreflight ok")
			}
			return nil
		},
	}
}

// labelFor maps a preflight Status to a CLI marker. We deliberately
// avoid emoji so the output is unambiguous in any terminal.
func labelFor(s preflight.Status) string {
	switch s {
	case preflight.StatusOK:
		return "[ OK ]"
	case preflight.StatusWarn:
		return "[WARN]"
	case preflight.StatusError:
		return "[ERR ]"
	default:
		return "[????]"
	}
}

func countStatus(r preflight.Result, s preflight.Status) int {
	n := 0
	for _, c := range r.Checks {
		if c.Status == s {
			n++
		}
	}
	return n
}
