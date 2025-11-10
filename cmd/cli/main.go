package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nfvault",
		Short: "A secure vault CLI for managing secrets",
		Long: `nfvault is a command-line interface for a secure vault service.
It allows you to store, retrieve, and manage secrets securely.`,
		SilenceUsage: true,
	}

	// Global flags
	cmd.PersistentFlags().String("server", "localhost:8443", "vault server address")
	cmd.PersistentFlags().Bool("insecure", false, "disable TLS verification (development only)")
	cmd.PersistentFlags().StringP("output", "o", "table", "output format (table, json, yaml)")
	cmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose output")

	// Add subcommands
	cmd.AddCommand(newLoginCmd())
	cmd.AddCommand(newLogoutCmd())
	cmd.AddCommand(newSecretCmd())
	cmd.AddCommand(newAuditCmd())
	cmd.AddCommand(newVersionCmd())

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Printf("nfvault version %s\n", version)
			cmd.Printf("commit: %s\n", commit)
			cmd.Printf("date: %s\n", date)
		},
	}
}