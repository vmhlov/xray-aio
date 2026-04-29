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
			r, err := preflight.Run(cmd.Context())
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "OS:        %s/%s\n", r.OS, r.Arch)
			fmt.Fprintf(out, "Distro:    %s (%s)\n", r.Distro, r.DistroName)
			for _, w := range r.Warnings {
				fmt.Fprintln(out, "WARN:     ", w)
			}
			for _, e := range r.Errors {
				fmt.Fprintln(out, "ERR:      ", e)
			}
			return err
		},
	}
}
