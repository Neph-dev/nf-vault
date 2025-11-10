// Package admin provides utilities for checking local admin privileges
package admin

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
)

// Checker provides methods to validate admin privileges
type Checker struct{}

// NewChecker creates a new admin privilege checker
func NewChecker() *Checker {
	return &Checker{}
}

// IsAdmin checks if the current user has administrative privileges
func (c *Checker) IsAdmin() (bool, error) {
	switch runtime.GOOS {
	case "windows":
		return c.isAdminWindows()
	case "darwin", "linux":
		return c.isAdminUnix()
	default:
		return false, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// RequireAdmin checks if the current user has admin privileges and returns an error if not
func (c *Checker) RequireAdmin() error {
	isAdmin, err := c.IsAdmin()
	if err != nil {
		return fmt.Errorf("failed to check admin privileges: %w", err)
	}
	
	if !isAdmin {
		return fmt.Errorf("administrative privileges required - please run nfvault as an administrator/root")
	}
	
	return nil
}

// isAdminUnix checks admin privileges on Unix-like systems (macOS, Linux)
func (c *Checker) isAdminUnix() (bool, error) {
	// Check if running as root (UID 0)
	if os.Getuid() == 0 {
		return true, nil
	}
	
	// Check if user is in admin/sudo group
	currentUser, err := user.Current()
	if err != nil {
		return false, fmt.Errorf("failed to get current user: %w", err)
	}
	
	groups, err := currentUser.GroupIds()
	if err != nil {
		return false, fmt.Errorf("failed to get user groups: %w", err)
	}
	
	// Check for common admin groups
	adminGroups := map[string]bool{
		"0":    true, // root group
		"80":   true, // admin group on macOS
		"8":    true, // admin group on some systems
		"27":   true, // sudo group on Linux
		"1000": true, // first user group (often has admin privileges)
	}
	
	for _, gid := range groups {
		if adminGroups[gid] {
			return true, nil
		}
		
		// Also check group names
		group, err := user.LookupGroupId(gid)
		if err == nil {
			if group.Name == "admin" || group.Name == "sudo" || group.Name == "wheel" {
				return true, nil
			}
		}
	}
	
	return false, nil
}

// isAdminWindows checks admin privileges on Windows
func (c *Checker) isAdminWindows() (bool, error) {
	// On Windows, we'll check if we can write to a system directory
	// This is a simple approach - for production use, you might want to use
	// Windows APIs like IsUserAnAdmin() or CheckTokenMembership()
	
	// Try to create a temporary file in System32
	testFile := `C:\Windows\System32\nfvault_admin_test.tmp`
	file, err := os.Create(testFile)
	if err != nil {
		// If we can't create in System32, we're not admin
		return false, nil
	}
	
	// Clean up the test file
	file.Close()
	os.Remove(testFile)
	
	return true, nil
}

// GetCurrentUser returns information about the current user
func (c *Checker) GetCurrentUser() (*user.User, error) {
	return user.Current()
}

// GetUserHomeDir returns the current user's home directory
func (c *Checker) GetUserHomeDir() (string, error) {
	return os.UserHomeDir()
}
