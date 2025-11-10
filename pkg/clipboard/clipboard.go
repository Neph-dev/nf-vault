package clipboard

import (
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

// ClipboardManager handles clipboard operations with auto-clear functionality
type ClipboardManager struct {
	autoClearDuration time.Duration
}

// NewClipboardManager creates a new clipboard manager
func NewClipboardManager(autoClearDuration time.Duration) *ClipboardManager {
	return &ClipboardManager{
		autoClearDuration: autoClearDuration,
	}
}

// SetContent sets the clipboard content and optionally auto-clears after duration
func (c *ClipboardManager) SetContent(content string) error {
	if err := c.setClipboard(content); err != nil {
		return fmt.Errorf("failed to set clipboard: %w", err)
	}

	if c.autoClearDuration > 0 {
		go c.autoClear()
	}

	return nil
}

// setClipboard sets the clipboard content based on the operating system
func (c *ClipboardManager) setClipboard(content string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin": // macOS
		cmd = exec.Command("pbcopy")
	case "linux":
		// Try xclip first, then xsel
		if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		} else if _, err := exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "--clipboard", "--input")
		} else {
			return fmt.Errorf("no clipboard utility found (xclip or xsel required on Linux)")
		}
	case "windows":
		cmd = exec.Command("clip")
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	cmd.Stdin = &contentReader{content: content}
	return cmd.Run()
}

// clearClipboard clears the clipboard content
func (c *ClipboardManager) clearClipboard() error {
	return c.setClipboard("")
}

// autoClear clears the clipboard after the specified duration
func (c *ClipboardManager) autoClear() {
	time.Sleep(c.autoClearDuration)
	if err := c.clearClipboard(); err != nil {
		// Log error but don't fail the application
		fmt.Printf("Warning: failed to auto-clear clipboard: %v\n", err)
	}
}

// contentReader implements io.Reader for string content
type contentReader struct {
	content string
	pos     int
}

func (r *contentReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.content) {
		return 0, nil // EOF
	}
	
	n = copy(p, r.content[r.pos:])
	r.pos += n
	return n, nil
}

// IsClipboardAvailable checks if clipboard functionality is available
func IsClipboardAvailable() bool {
	switch runtime.GOOS {
	case "darwin":
		_, err := exec.LookPath("pbcopy")
		return err == nil
	case "linux":
		_, err1 := exec.LookPath("xclip")
		_, err2 := exec.LookPath("xsel")
		return err1 == nil || err2 == nil
	case "windows":
		_, err := exec.LookPath("clip")
		return err == nil
	default:
		return false
	}
}