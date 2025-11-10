# nfvault

A secure, local secret management tool designed for system administrators. nfvault provides a simple command-line interface to store, retrieve, and manage sensitive information like passwords, API keys, and other secrets with admin-level security.

## 🔐 Security Model

nfvault uses a **local-only, admin-privilege security model**:

- **Admin Access Control**: Only users with local administrator privileges can access the vault
- **Local Storage**: All secrets are stored locally in an SQLite database (`~/.nf-vault/vault.db`)
- **No Network Dependencies**: Operates entirely offline - no remote servers or network connections required
- **Simplified Security**: No master passwords or complex encryption - relies on OS-level admin controls

## 📋 Features

- **🔒 Secure Storage**: Store passwords, API keys, tokens, and other sensitive data
- **🏷️ Organized Management**: Categorize secrets and add tags for easy organization
- **🔍 Flexible Retrieval**: Find secrets by name or ID with optional data inclusion
- **⚡ Fast Operations**: Direct SQLite access for instant secret management
- **📊 Multiple Output Formats**: Support for table, JSON, and YAML output
- **🖥️ Cross-Platform**: Works on Windows, macOS, and Linux
- **📝 Rich Metadata**: Store descriptions, categories, and tags with each secret

## 📦 Installation

### Prerequisites

- Go 1.21 or higher
- Local administrator privileges on your system

### Build from Source

```bash
git clone https://github.com/Neph-dev/nf-vault.git
cd nf-vault
go build -o nfvault ./cmd/cli
```

### Install Binary

```bash
# Move the binary to your PATH
sudo mv nfvault /usr/local/bin/
# or on Windows, move to a directory in your PATH
```

## 🚀 Quick Start

### Create Your First Secret

```bash
# Create a simple secret
nfvault secret create "api-key" "sk-1234567890abcdef"

# Create a secret with metadata
nfvault secret create "db-password" "super-secure-password" \
  --category="database" \
  --tag="production" \
  --tag="mysql" \
  --description="Production MySQL password"
```

### Retrieve Secrets

```bash
# Get secret metadata
nfvault secret get "api-key"

# Get secret with data
nfvault secret get "api-key" --data

# Output as JSON
nfvault secret get "api-key" --data --output=json
```

### List All Secrets

```bash
# List all secrets
nfvault secret list

# List with JSON output
nfvault secret list --output=json
```

### Update Secrets

```bash
# Update secret data
nfvault secret update "api-key" "new-api-key-value"

# Update metadata only
nfvault secret update "api-key" --category="external" --tag="staging"

# Update both data and metadata
nfvault secret update "api-key" "updated-key-123" --category="api" --tag="v2"
```

### Delete Secrets

```bash
# Delete by name
nfvault secret delete "api-key"

# Delete by ID
nfvault secret delete "550e8400-e29b-41d4-a716-446655440000"
```

## 📖 Command Reference

### Global Flags

- `--output, -o`: Output format (table, json, yaml) [default: table]
- `--verbose, -v`: Enable verbose output
- `--help, -h`: Show help information

### Secret Commands

#### `nfvault secret create [name] [data]`

Create a new secret with optional metadata.

**Flags:**
- `--category, -c`: Secret category (e.g., "password", "api", "token")
- `--description, -d`: Secret description
- `--tag, -t`: Secret tags (can be used multiple times)
- `--file, -f`: Read data from file instead of command line

**Examples:**
```bash
# Basic secret
nfvault secret create "github-token" "ghp_xxxxxxxxxxxx"

# With metadata
nfvault secret create "db-config" "user:pass@localhost:5432/mydb" \
  --category="database" \
  --description="Production database connection" \
  --tag="production" \
  --tag="postgresql"

# From file
nfvault secret create "ssl-cert" --file="/path/to/certificate.pem" \
  --category="certificate"

# From stdin
echo "secret-value" | nfvault secret create "pipe-secret" -
```

#### `nfvault secret get [id-or-name]`

Retrieve a secret by ID or name.

**Flags:**
- `--data, -d`: Include secret data in output
- `--copy, -c`: Copy secret data to clipboard (requires --data)
- `--clear-after`: Auto-clear clipboard after specified duration (e.g., "30s", "5m")

**Examples:**
```bash
# Get metadata only
nfvault secret get "github-token"

# Get with data
nfvault secret get "github-token" --data

# Copy to clipboard and clear after 30 seconds
nfvault secret get "github-token" --copy --clear-after=30s
```

#### `nfvault secret update [id-or-name] [new-data]`

Update an existing secret's data and/or metadata.

**Flags:**
- `--category, -c`: Update category
- `--description, -d`: Update description
- `--tag, -t`: Update tags (replaces existing tags)
- `--file, -f`: Read new data from file

**Examples:**
```bash
# Update data only
nfvault secret update "github-token" "ghp_new_token_value"

# Update metadata only
nfvault secret update "github-token" --category="token" --tag="personal"

# Update both
nfvault secret update "github-token" "ghp_latest_token" --description="Updated token"
```

#### `nfvault secret delete [id-or-name]`

Delete a secret by ID or name.

**Examples:**
```bash
# Delete by name
nfvault secret delete "old-api-key"

# Delete by ID
nfvault secret delete "550e8400-e29b-41d4-a716-446655440000"
```

#### `nfvault secret list`

List all secrets with their metadata.

**Flags:**
- `--category, -c`: Filter by category
- `--tag, -t`: Filter by tag

**Examples:**
```bash
# List all secrets
nfvault secret list

# Filter by category
nfvault secret list --category="database"

# Filter by tag
nfvault secret list --tag="production"

# JSON output
nfvault secret list --output=json
```

### Other Commands

#### `nfvault audit`

View audit logs of vault operations.

#### `nfvault version`

Display version information.

#### `nfvault completion`

Generate shell completion scripts.

```bash
# Bash completion
nfvault completion bash > ~/.nfvault-completion.bash
echo 'source ~/.nfvault-completion.bash' >> ~/.bashrc

# Zsh completion
nfvault completion zsh > "${fpath[1]}/_nfvault"

# Fish completion
nfvault completion fish > ~/.config/fish/completions/nfvault.fish
```

## 📁 File Locations

- **Database**: `~/.nf-vault/vault.db` - SQLite database containing all secrets
- **Logs**: `~/.nf-vault/logs/` - Application logs (if enabled)

## ⚙️ Configuration

nfvault uses sensible defaults and doesn't require configuration files. All settings are controlled via command-line flags.

### Environment Variables

Currently, nfvault doesn't use environment variables for configuration, maintaining its simple, local-only approach.

## 🔧 Development

### Project Structure

```
nf-vault/
├── cmd/
│   ├── cli/           # CLI application code
│   └── server/        # Server code (legacy, not used in local mode)
├── pkg/
│   ├── admin/         # Admin privilege checking
│   ├── auth/          # Authentication utilities
│   ├── clipboard/     # Clipboard management
│   ├── crypto/        # Cryptographic utilities (legacy)
│   ├── local/         # Local SQLite client
│   └── store/         # Data storage layer
├── proto/             # Protocol buffer definitions
├── gen/               # Generated protobuf code
└── migrations/        # Database migrations
```

### Building

```bash
# Build CLI
go build -o nfvault ./cmd/cli

# Build server (legacy)
go build -o nf-vault-server ./cmd/server

# Build both
make build

# Run tests
go test ./...

# Run with verbose output
go run ./cmd/cli secret list --verbose
```

### Dependencies

- **SQLite**: Local database storage
- **Cobra**: CLI framework
- **UUID**: Unique identifier generation
- **Crypto**: Security utilities
- **Protobuf**: Data serialization

## 🛡️ Security Considerations

### Admin Privilege Requirements

nfvault requires local administrator privileges to access secrets. This means:

- **Windows**: Must run as Administrator or have admin rights
- **macOS/Linux**: Must run with sudo or be in admin/wheel group
- **Access Control**: Only admin users can read/write secrets

### Local Storage Security

- Secrets are stored in a local SQLite database
- Database file permissions are restricted to the owner
- No encryption is applied - security relies on OS-level access controls
- Data is stored in plain text within the protected database file

### Best Practices

1. **Backup**: Regularly backup your `~/.nf-vault/vault.db` file
2. **File Permissions**: Ensure the vault directory has restricted permissions
3. **System Security**: Keep your operating system and security patches up to date
4. **Access Control**: Only grant admin privileges to trusted users
5. **Audit**: Regularly review audit logs for unauthorized access attempts

## 🐛 Troubleshooting

### Common Issues

**"Permission denied" errors:**
```bash
# Ensure you have admin privileges
sudo nfvault secret list  # Linux/macOS
# Run as Administrator on Windows
```

**"Secret not found" errors:**
```bash
# List all secrets to verify names
nfvault secret list

# Use exact ID if name matching fails
nfvault secret get "550e8400-e29b-41d4-a716-446655440000"
```

**Database access issues:**
```bash
# Check if vault directory exists and is accessible
ls -la ~/.nf-vault/

# Verify database file permissions
ls -la ~/.nf-vault/vault.db
```

### Debug Mode

Enable verbose output for troubleshooting:

```bash
nfvault secret list --verbose
```

### Log Files

Check application logs in `~/.nf-vault/logs/` for detailed error information.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/Neph-dev/nf-vault.git
cd nf-vault
go mod download
go build ./cmd/cli
./nfvault --help
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Cobra](https://github.com/spf13/cobra) CLI framework
- Uses [SQLite](https://www.sqlite.org/) for reliable local storage
- Inspired by the need for simple, secure local secret management

---

**Made with ❤️ for system administrators who need secure, local secret management.**
