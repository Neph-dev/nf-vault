package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	vault "github.com/Neph-dev/nef-vault/gen/vault/v1"
	cliputil "github.com/Neph-dev/nef-vault/pkg/clipboard"
	"github.com/Neph-dev/nef-vault/pkg/local"
	"github.com/spf13/cobra"
)

func newSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage secrets in the vault",
		Long:  "Create, read, update, delete and list secrets stored in the vault.",
	}

	cmd.AddCommand(newSecretCreateCmd())
	cmd.AddCommand(newSecretGetCmd())
	cmd.AddCommand(newSecretUpdateCmd())
	cmd.AddCommand(newSecretDeleteCmd())
	cmd.AddCommand(newSecretListCmd())

	return cmd
}

func newSecretCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create [name] [data]",
		Short: "Create a new secret",
		Long: `Create a new secret with the specified name and data.
Data can be provided as a string or read from stdin with '-'.`,
		Args: cobra.RangeArgs(1, 2),
		RunE: runSecretCreate,
	}

	cmd.Flags().StringP("category", "c", "", "secret category")
	cmd.Flags().StringP("description", "d", "", "secret description")
	cmd.Flags().StringArrayP("tag", "t", nil, "secret tags (can be used multiple times)")
	cmd.Flags().StringP("file", "f", "", "read data from file")

	return cmd
}

func runSecretCreate(cmd *cobra.Command, args []string) error {
	name := args[0]
	var data []byte
	var err error

	// Get data source
	if file, _ := cmd.Flags().GetString("file"); file != "" {
		data, err = os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
	} else if len(args) > 1 {
		if args[1] == "-" {
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read from stdin: %w", err)
			}
		} else {
			data = []byte(args[1])
		}
	} else {
		return fmt.Errorf("no data provided")
	}

	// Get flags
	category, _ := cmd.Flags().GetString("category")
	description, _ := cmd.Flags().GetString("description")
	tags, _ := cmd.Flags().GetStringArray("tag")

	// Create secret
	secret := &vault.Secret{
		Name: name,
		Metadata: &vault.SecretMetadata{
			Category:    category,
			Description: description,
			Tags:        tags,
		},
	}

	vaultClient, err := createLocalClient(cmd)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	createdSecret, err := vaultClient.CreateSecret(ctx, secret, data)
	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}

	fmt.Printf("Secret created: %s (ID: %s)\n", createdSecret.Name, createdSecret.Id)
	return nil
}

func newSecretGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [id-or-name]",
		Short: "Get a secret by ID or name",
		Args:  cobra.ExactArgs(1),
		RunE:  runSecretGet,
	}

	cmd.Flags().BoolP("data", "d", false, "include secret data in output")
	cmd.Flags().StringP("output", "o", "table", "output format (table, json)")
	cmd.Flags().BoolP("copy", "c", false, "copy secret data to clipboard")
	cmd.Flags().DurationP("clear-after", "", 30*time.Second, "auto-clear clipboard after duration (0 to disable)")

	return cmd
}

func runSecretGet(cmd *cobra.Command, args []string) error {
	identifier := args[0]
	includeData, _ := cmd.Flags().GetBool("data")
	output, _ := cmd.Flags().GetString("output")
	copyToClip, _ := cmd.Flags().GetBool("copy")
	clearAfter, _ := cmd.Flags().GetDuration("clear-after")

	// If copying to clipboard, we need the data
	if copyToClip {
		includeData = true
	}

	vaultClient, err := createLocalClient(cmd)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret, data, err := vaultClient.GetSecret(ctx, identifier, includeData)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	// Handle clipboard operations
	if copyToClip && data != nil {
		if !cliputil.IsClipboardAvailable() {
			fmt.Println("Warning: Clipboard functionality not available on this system")
		} else {
			clipManager := cliputil.NewClipboardManager(clearAfter)
			if err := clipManager.SetContent(string(data)); err != nil {
				fmt.Printf("Warning: Failed to copy to clipboard: %v\n", err)
			} else {
				if clearAfter > 0 {
					fmt.Printf("Secret copied to clipboard (will auto-clear in %v)\n", clearAfter)
				} else {
					fmt.Println("Secret copied to clipboard")
				}
				
				// If we're only copying, don't display the data
				if output == "table" && !cmd.Flags().Changed("data") {
					includeData = false
				}
			}
		}
	}

	return displaySecret(secret, data, output, includeData)
}

func newSecretUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update [id-or-name] [data]",
		Short: "Update an existing secret",
		Args:  cobra.RangeArgs(1, 2),
		RunE:  runSecretUpdate,
	}

	cmd.Flags().StringP("category", "c", "", "secret category")
	cmd.Flags().StringP("description", "d", "", "secret description")
	cmd.Flags().StringArrayP("tag", "t", nil, "secret tags (can be used multiple times)")
	cmd.Flags().StringP("file", "f", "", "read data from file")

	return cmd
}

func runSecretUpdate(cmd *cobra.Command, args []string) error {
	identifier := args[0]
	
	vaultClient, err := createLocalClient(cmd)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get existing secret (metadata only)
	secret, _, err := vaultClient.GetSecret(ctx, identifier, false)
	if err != nil {
		return fmt.Errorf("failed to get existing secret: %w", err)
	}

	// Update fields from flags
	if secret.Metadata == nil {
		secret.Metadata = &vault.SecretMetadata{}
	}
	if category, _ := cmd.Flags().GetString("category"); category != "" {
		secret.Metadata.Category = category
	}
	if description, _ := cmd.Flags().GetString("description"); description != "" {
		secret.Metadata.Description = description
	}
	if tags, _ := cmd.Flags().GetStringArray("tag"); len(tags) > 0 {
		secret.Metadata.Tags = tags
	}

	// Get data if provided
	var data []byte
	if file, _ := cmd.Flags().GetString("file"); file != "" {
		data, err = os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
	} else if len(args) > 1 {
		if args[1] == "-" {
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read from stdin: %w", err)
			}
		} else {
			data = []byte(args[1])
		}
	}

	updatedSecret, err := vaultClient.UpdateSecret(ctx, secret, data)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	fmt.Printf("Secret updated: %s (ID: %s)\n", updatedSecret.Name, updatedSecret.Id)
	return nil
}

func newSecretDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete [id-or-name]",
		Short: "Delete a secret by ID or name",
		Args:  cobra.ExactArgs(1),
		RunE:  runSecretDelete,
	}
}

func runSecretDelete(cmd *cobra.Command, args []string) error {
	identifier := args[0]

	vaultClient, err := createLocalClient(cmd)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get secret first to confirm it exists and get its name
	secret, _, err := vaultClient.GetSecret(ctx, identifier, false)
	if err != nil {
		return fmt.Errorf("failed to find secret: %w", err)
	}

	if err := vaultClient.DeleteSecret(ctx, secret.Id); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	fmt.Printf("Secret deleted: %s (ID: %s)\n", secret.Name, secret.Id)
	return nil
}

func newSecretListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all secrets",
		RunE:  runSecretList,
	}

	cmd.Flags().StringP("output", "o", "table", "output format (table, json)")
	cmd.Flags().Int32P("limit", "l", 50, "maximum number of secrets to return")

	return cmd
}

func runSecretList(cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")
	limit, _ := cmd.Flags().GetInt32("limit")

	vaultClient, err := createLocalClient(cmd)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secrets, _, err := vaultClient.ListSecrets(ctx, limit, "")
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	return displaySecrets(secrets, output)
}

// Helper functions

func createLocalClient(cmd *cobra.Command) (*local.LocalClient, error) {
	// Get database path from root flags
	dbPath, _ := cmd.Root().PersistentFlags().GetString("database")
	if dbPath == "" {
		// Use default configuration (will use ~/.nef-vault)
		return local.NewLocalClient(&local.Config{})
	}
	
	// Extract directory from the full database path
	dataDir := filepath.Dir(dbPath)
	return local.NewLocalClient(&local.Config{
		DataDir: dataDir,
	})
}

func displaySecret(secret *vault.Secret, data []byte, format string, includeData bool) error {
	switch format {
	case "json":
		result := map[string]interface{}{
			"id":         secret.Id,
			"name":       secret.Name,
			"created_at": secret.CreatedAt,
			"updated_at": secret.UpdatedAt,
		}
		if secret.Metadata != nil {
			result["category"] = secret.Metadata.Category
			result["description"] = secret.Metadata.Description
			result["tags"] = secret.Metadata.Tags
		}
		if includeData && data != nil {
			result["data"] = string(data)
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	default: // table
		fmt.Printf("ID:          %s\n", secret.Id)
		fmt.Printf("Name:        %s\n", secret.Name)
		if secret.Metadata != nil {
			fmt.Printf("Category:    %s\n", secret.Metadata.Category)
			fmt.Printf("Description: %s\n", secret.Metadata.Description)
			fmt.Printf("Tags:        %s\n", strings.Join(secret.Metadata.Tags, ", "))
		}
		fmt.Printf("Created:     %s\n", secret.CreatedAt.AsTime().Format(time.RFC3339))
		fmt.Printf("Updated:     %s\n", secret.UpdatedAt.AsTime().Format(time.RFC3339))
		if includeData && data != nil {
			fmt.Printf("Data:        %s\n", string(data))
		}
		return nil
	}
}

func displaySecrets(secrets []*vault.Secret, format string) error {
	switch format {
	case "json":
		return json.NewEncoder(os.Stdout).Encode(secrets)
	default: // table
		if len(secrets) == 0 {
			fmt.Println("No secrets found")
			return nil
		}
		
		fmt.Printf("%-36s %-20s %-15s %s\n", "ID", "NAME", "CATEGORY", "DESCRIPTION")
		fmt.Println(strings.Repeat("-", 80))
		for _, secret := range secrets {
			var category, description string
			if secret.Metadata != nil {
				category = secret.Metadata.Category
				description = secret.Metadata.Description
			}
			if len(description) > 30 {
				description = description[:27] + "..."
			}
			fmt.Printf("%-36s %-20s %-15s %s\n", 
				secret.Id, secret.Name, category, description)
		}
		return nil
	}
}