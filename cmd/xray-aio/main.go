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
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/vmhlov/xray-aio/internal/log"
	"github.com/vmhlov/xray-aio/internal/preflight"
	"github.com/vmhlov/xray-aio/internal/state"
	"github.com/vmhlov/xray-aio/internal/transport"
	"github.com/vmhlov/xray-aio/internal/version"
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
	var (
		profile string
		domain  string
		email   string
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install one of the predefined profiles on this host",
		RunE: func(cmd *cobra.Command, _ []string) error {
			log.L().Info("install requested", "profile", profile, "domain", domain)
			fmt.Fprintln(cmd.OutOrStdout(), "install: not implemented yet (Phase 0 skeleton)")
			fmt.Fprintln(cmd.OutOrStdout(), "available transports:", transport.Names())
			return nil
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "home-stealth", "preset profile (home-stealth|home-mobile|home-cdn|bridge-ru-eu|paranoid)")
	cmd.Flags().StringVar(&domain, "domain", "", "domain name for selfsteal/ACME (required for most transports)")
	cmd.Flags().StringVar(&email, "email", "", "email for Let's Encrypt registration")
	return cmd
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show installed transports and their health",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := state.Load()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "schema=%d profile=%q domain=%q transports=%d\n",
				s.Schema, s.Profile, s.Domain, len(s.Transports))
			return nil
		},
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
