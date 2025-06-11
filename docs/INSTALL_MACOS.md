# Installing LogManticsAI on macOS

Since LogManticsAI is primarily designed for Linux systems, on macOS we recommend using the local installation package.

## Installation Steps

```bash
# Download the local installation package
wget https://github.com/yourusername/logmanticsai/releases/download/v0.1.0/logmanticsai_local_package.zip

# Extract the package
unzip logmanticsai_local_package.zip

# Run the installer
./install.sh
```

This will install LogManticsAI to your `~/.local/bin` directory. Make sure this directory is in your PATH:

```bash
# Add this to your ~/.zshrc or ~/.bash_profile
export PATH=$PATH:~/.local/bin

# Then reload your shell configuration
source ~/.zshrc  # or source ~/.bash_profile
```

## Dependencies

LogManticsAI requires Python 3.8 or higher. If you don't have Python installed, we recommend using Homebrew:

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python@3.9
```

## Building From Source

If you prefer to build the package yourself:

```bash
# Clone the repository
git clone https://github.com/yourusername/logmanticsai.git
cd logmanticsai

# Build the local package
./scripts/local_build.sh

# This will create logmanticsai_local_package.zip
# Extract and install as described above
```

## Usage

After installation, you can use LogManticsAI with the following commands:

```bash
# Initialize and configure
logmanticsai-init

# Monitor logs
logmanticsai-monitor

# Manage configuration
logmanticsai-config

# Access all commands
logmanticsai-cli --help
```

## Troubleshooting

If you encounter any issues:

1. Make sure Python 3.8+ is installed and in your PATH:
   ```bash
   python3 --version
   ```

2. Check if the dependencies were installed correctly:
   ```bash
   pip3 list | grep -E 'agno|openai|watchdog|slack-sdk'
   ```

3. Verify the logmanticsai commands are available:
   ```bash
   which logmanticsai-init
   ```

4. If commands are not found, ensure ~/.local/bin is in your PATH:
   ```bash
   echo $PATH | grep -q "$HOME/.local/bin" || echo "~/.local/bin is not in your PATH"
   ```

For more help, please open an issue on our [GitHub repository](https://github.com/yourusername/logmanticsai/issues). 