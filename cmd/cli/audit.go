package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "View audit logs (disabled)",
		Long:  "Audit functionality is not available in local-only mode.",
		RunE:  runAudit,
	}

	cmd.Flags().StringP("output", "o", "table", "output format (table, json)")
	cmd.Flags().Int32P("limit", "l", 50, "maximum number of entries to return")

	return cmd
}

func runAudit(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("audit functionality is not available in local-only mode")
}