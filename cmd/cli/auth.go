package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newLoginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login [username]",
		Short: "Authenticate with the vault server (disabled)",
		Long:  "Login functionality is not available in local-only mode. Operations now require local admin privileges.",
		RunE:  runLogin,
	}

	return cmd
}

func runLogin(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("login functionality is not available in local-only mode")
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out from the vault server (disabled)",
		Long:  "Logout functionality is not available in local-only mode.",
		RunE:  runLogout,
	}
}

func runLogout(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("logout functionality is not available in local-only mode")
}