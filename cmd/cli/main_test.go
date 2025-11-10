package main

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
)

func TestCLICommands(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "help command",
			args:     []string{"--help"},
			wantErr:  false,
			contains: "nfvault is a command-line interface",
		},
		{
			name:     "version command",
			args:     []string{"version"},
			wantErr:  false,
			contains: "version dev",
		},
		{
			name:     "secret help",
			args:     []string{"secret", "--help"},
			wantErr:  false,
			contains: "Create, read, update, delete and list secrets",
		},
		{
			name:     "login help",
			args:     []string{"login", "--help"},
			wantErr:  false,
			contains: "Login to the vault server",
		},
		{
			name:     "audit help",
			args:     []string{"audit", "--help"},
			wantErr:  false,
			contains: "Retrieve and display audit logs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRootCmd()
			cmd.SetArgs(tt.args)
			
			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("command error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			output := buf.String()
			if tt.contains != "" && !bytes.Contains([]byte(output), []byte(tt.contains)) {
				t.Errorf("expected output to contain %q, got %q", tt.contains, output)
			}
		})
	}
}

func TestSecretCommands(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "secret create help",
			args:     []string{"secret", "create", "--help"},
			wantErr:  false,
			contains: "Create a new secret",
		},
		{
			name:     "secret get help",
			args:     []string{"secret", "get", "--help"},
			wantErr:  false,
			contains: "Get a secret by ID or name",
		},
		{
			name:     "secret list help",
			args:     []string{"secret", "list", "--help"},
			wantErr:  false,
			contains: "List all secrets",
		},
		{
			name:     "secret update help",
			args:     []string{"secret", "update", "--help"},
			wantErr:  false,
			contains: "Update an existing secret",
		},
		{
			name:     "secret delete help",
			args:     []string{"secret", "delete", "--help"},
			wantErr:  false,
			contains: "Delete a secret by ID or name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRootCmd()
			cmd.SetArgs(tt.args)
			
			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("command error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			output := buf.String()
			if tt.contains != "" && !bytes.Contains([]byte(output), []byte(tt.contains)) {
				t.Errorf("expected output to contain %q, got %q", tt.contains, output)
			}
		})
	}
}

func TestClipboardGetFlags(t *testing.T) {
	cmd := newSecretGetCmd()
	
	// Test that clipboard flags are available
	copyFlag := cmd.Flags().Lookup("copy")
	if copyFlag == nil {
		t.Error("expected --copy flag to be available")
	}
	
	clearAfterFlag := cmd.Flags().Lookup("clear-after")
	if clearAfterFlag == nil {
		t.Error("expected --clear-after flag to be available")
	}
}

func TestCommandStructure(t *testing.T) {
	root := newRootCmd()
	
	// Test that all expected commands are available
	expectedCommands := []string{"login", "logout", "secret", "audit", "version"}
	
	for _, cmdName := range expectedCommands {
		found := false
		for _, cmd := range root.Commands() {
			if cmd.Name() == cmdName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected command %q to be available", cmdName)
		}
	}
	
	// Test secret subcommands
	var secretCmd *cobra.Command
	for _, cmd := range root.Commands() {
		if cmd.Name() == "secret" {
			secretCmd = cmd
			break
		}
	}
	
	if secretCmd == nil {
		t.Fatal("secret command not found")
	}
	
	expectedSecretCommands := []string{"create", "get", "update", "delete", "list"}
	for _, cmdName := range expectedSecretCommands {
		found := false
		for _, cmd := range secretCmd.Commands() {
			if cmd.Name() == cmdName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected secret subcommand %q to be available", cmdName)
		}
	}
}