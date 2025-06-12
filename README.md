# LLM-Powered Log Analysis Tool

A command-line tool that intelligently analyzes JSON log files by leveraging LLMs.

## Features

- Interactive setup for LLM configuration and log file paths
- Support for monitoring multiple log files simultaneously
- Secure storage of API keys using keyring
- JSON log validation and structure analysis
- LLM-assisted identification of important log keys
- Continuous log monitoring with real-time anomaly detection
- Support for multiple LLM providers via Agno (OpenAI, Anthropic, Google, Groq)
- Slack integration for real-time notifications
- Custom severity level and status code detection

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd LogManticsAI

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install the tool
pip install -e .
```

## Usage

### 1. Setup and Configuration

```bash
LogManticsAI setup
```

This interactive command guides you through:
- Selecting the LLM model (e.g., gpt-4, claude-3-sonnet)
- Providing your LLM API key (stored securely using keyring)
- Setting up log files for monitoring
- Configuring log level filtering and status code handling
- Optionally setting up Slack integration

Non-interactive setup options:

```bash
# Single log file
LogManticsAI setup --model gpt-4 --provider OPENAI --api-key YOUR_API_KEY --log-paths /path/to/app.log --non-interactive

# Multiple log files (space-separated)
LogManticsAI setup --model gpt-4 --api-key YOUR_API_KEY --log-paths "/path/to/app.log /path/to/api.log" --non-interactive

# With wildcard pattern support
LogManticsAI setup --model claude-3-sonnet-20240229 --provider ANTHROPIC --api-key YOUR_API_KEY --log-paths "/var/log/*.json" --non-interactive

# With custom critical levels and status codes
LogManticsAI setup --model gpt-4 --api-key YOUR_API_KEY --log-paths /path/to/app.log \
  --critical-levels ERROR CRITICAL FATAL --normal-status-codes 200 201 204 --non-interactive
```

### 2. Monitor Logs

```bash
LogManticsAI-monitor
```

This command:
- Monitors all configured log files for new entries
- Processes entries, focusing on important keys
- Batches entries for efficient LLM analysis
- Alerts about anomalies, errors, and security issues
- Saves analysis reports to `~/.config/LogManticsAI/results/`
- Sends Slack notifications (if enabled)

Enable debug logging:
```bash
LogManticsAI-monitor --debug
```

### 3. Manage Configuration

View current configuration:
```bash
LogManticsAI-config --show
```

Manage log files:
```bash
# Add a new log file
LogManticsAI-config --add-log-file /path/to/new.log

# Remove a log file
LogManticsAI-config --remove-log-file /path/to/old.log

# List all monitored log files
LogManticsAI-config --list-log-files
```

Reset configuration:
```bash
LogManticsAI-config --reset
```

Slack integration:
```bash
# Enable/disable notifications
LogManticsAI-config --slack-enable
LogManticsAI-config --slack-disable

# Update settings
LogManticsAI-config --slack-channel="#new-channel-name"
LogManticsAI-config --slack-token="xoxb-your-token"
```

Test Slack integration:
```bash
LogManticsAI slack-test
```

### 4. Anomaly Detection Configuration

Configure anomaly detection settings with the following commands:
```bash
# Set batch size for log analysis (how many logs to analyze in each batch)
LogManticsAI-config --batch-size 50

# Set analysis interval in seconds (how often logs are analyzed)
LogManticsAI-config --analysis-interval 120

# Configure error rate threshold (errors/minute before alerting)
LogManticsAI-config --error-rate-threshold 5

# Configure response time threshold in milliseconds
LogManticsAI-config --response-time-threshold 1000

# Enable/disable processing of existing logs on startup
LogManticsAI-config --process-existing-logs true
```

You can verify your current settings with:
```bash
LogManticsAI-config --show
```

#### Batch Size
The `--batch-size` option controls how many log entries are analyzed together in a single batch by the LLM:

- **Lower values** (e.g., 10-30): Provide more frequent, granular analysis but may increase API costs and reduce context for pattern recognition.
- **Higher values** (e.g., 100-200): Allow the LLM to see more logs at once, improving pattern detection across entries, but result in less frequent updates.
- **Default**: 100 log entries per batch

Example: Setting batch size to 50 means the LLM will analyze logs in groups of up to 50 entries:
```bash
LogManticsAI-config --batch-size 50
```

#### Analysis Interval
The `--analysis-interval` option sets how frequently (in seconds) log batches are sent to the LLM for analysis:

- **Lower values** (e.g., 30-60): More frequent analysis and faster alerts, but higher API usage and costs.
- **Higher values** (e.g., 300-600): Less frequent analysis with lower costs, but longer delay before detecting issues.
- **Default**: 300 seconds (5 minutes)

Example: Setting interval to 120 seconds means logs will be analyzed at least every 2 minutes:
```bash
LogManticsAI-config --analysis-interval 120
```

#### How Batch Size and Analysis Interval Work Together

The system analyzes logs when either condition is met:

1. **Batch Size Reached First**: If your logs reach the batch size limit before the analysis interval expires, analysis happens immediately without waiting for the interval.

2. **Analysis Interval Reached First**: If the analysis interval time is reached before collecting a full batch, the system analyzes whatever logs are available, even if the batch is partially filled.

This approach ensures:
- During high traffic periods: Frequent analysis as batches fill quickly
- During low traffic periods: Timely analysis even when log volume is low

Choosing the right balance depends on your application's log volume and how quickly you need to detect issues:
```bash
# High volume, cost-conscious configuration
LogManticsAI-config --batch-size 200 --analysis-interval 600

# Low volume, quick detection configuration
LogManticsAI-config --batch-size 20 --analysis-interval 60
```

#### Response Time Threshold
The `--response-time-threshold` option defines the maximum acceptable response time in milliseconds. Log entries with longer response times will be flagged as potential performance issues:

- **Lower values** (e.g., 200-500ms): Stricter performance requirements for low-latency applications.
- **Higher values** (e.g., 2000-5000ms): More lenient for applications where longer response times are acceptable.
- **Default**: 1000ms (1 second)

Example: Setting threshold to 1000ms means responses taking longer than 1 second will be highlighted:
```bash
LogManticsAI-config --response-time-threshold 1000
```

### 4.1 Error Rate Threshold Explained

The error rate threshold sets a limit on how many error logs per minute are considered acceptable. When this threshold is exceeded, the system triggers alerts and notifications.

**How it works:**
- The system tracks all logs with level "ERROR" or "CRITICAL"
- Calculates errors per minute during the monitoring interval
- If errors/minute exceeds the threshold, triggers an alert
- Resets the counter after each analysis interval

**Example scenarios:**

1. **Low Traffic Application (threshold = 2)**
   ```
   # Configure low threshold for critical services
   LogManticsAI-config --error-rate-threshold 2
   ```
   In this scenario, if your application logs more than 2 errors per minute (e.g., 5 errors in 2 minutes = 2.5 errors/min), you'll receive an alert.

2. **High Traffic Application (threshold = 10)**
   ```
   # Configure higher threshold for high-volume services
   LogManticsAI-config --error-rate-threshold 10
   ```
   For applications with high traffic where some errors are expected, a higher threshold prevents alert fatigue.

3. **Zero Tolerance Setting (threshold = 0.1)**
   ```
   # Configure for mission-critical systems with near-zero tolerance
   LogManticsAI-config --error-rate-threshold 0.1
   ```
   This setting would alert if more than 1 error occurs in 10 minutes, suitable for mission-critical systems.

When an error rate threshold is violated, LogManticsAI will:
1. Log a warning message
2. Send a Slack notification (if configured)
3. Include details about the current error rate vs. threshold
4. Reset the error count after the notification

### 5. Results and Reports

Analysis results are saved to:
```
~/.config/LogManticsAI/results/
```

Each analysis file includes:
- Timestamp and source log file name
- Formatted analysis with severity level
- Detected anomalies and recommendations
- Raw LLM analysis output
- The log entries that were analyzed

View recent results:
```bash
# List all analysis files
ls -la ~/.config/LogManticsAI/results/

# View most recent analysis
cat ~/.config/LogManticsAI/results/$(ls -t ~/.config/LogManticsAI/results/ | head -1)
```

## Quick Start with Demo Scripts

### 1. Generate Sample Logs

```bash
# Generate one-time log files
python scripts/generate_sample_logs.py --output-dir logs --count 1000

# Generate logs continuously
python scripts/generate_sample_logs.py --output-dir logs --continuous --interval 1.0

# Generate logs without anomaly patterns
python scripts/generate_sample_logs.py --output-dir logs --no-patterns
```

This creates three log files:
- `app_logs.json`: Standard application logs
- `api_logs.json`: API logs with custom levels
- `security_logs.json`: Security-focused logs

### 2. Run the Demo

```bash
# Analyze a single log file
python scripts/demo.py --log-paths logs/app_logs.json --api-key YOUR_API_KEY

# Analyze multiple log files
python scripts/demo.py --log-paths logs/app_logs.json logs/api_logs.json --api-key YOUR_API_KEY

# Monitor with custom configuration and Slack notifications
python scripts/demo.py \
  --log-paths logs/app_logs.json logs/api_logs.json \
  --api-key YOUR_API_KEY \
  --monitor \
  --interval 60 \
  --critical-levels WARNING ERROR CRITICAL FATAL SEVERE \
  --normal-status-codes 200 201 204 \
  --slack-token "xoxb-your-slack-token" \
  --slack-channel "#your-channel"
```

## Supported LLM Providers

- **OpenAI** (default): GPT-4, GPT-3.5 Turbo
- **Anthropic**: Claude 3 (Opus, Sonnet, Haiku)
- **Google**: Gemini models
- **Groq**: LLaMA2, Mixtral models

## Project Structure

```
LogManticsAI/
├── LogManticsAI/            # Main application package
│   ├── __init__.py
│   ├── main.py             # CLI entry points using Click
│   ├── config.py           # Configuration management
│   ├── setup_tool.py       # Setup and key identification
│   ├── monitoring.py       # Continuous log monitoring
│   ├── llm_utils.py        # LLM interaction utilities
│   ├── agno_utils.py       # Agno model and agent utilities
│   └── utils.py            # Common utility functions
├── tests/                  # Unit and integration tests
├── scripts/                # Helper scripts
├── README.md
├── requirements.txt
└── setup.py                # For packaging
```

## How It Works

1. **Setup**: Configure LLM provider and model, securely store API key, specify log files, and optionally configure Slack.

2. **Initial Analysis**: For each log file:
   - Validate JSON format and identify common keys
   - Use LLM to determine important keys for monitoring
   - Configure critical log levels and normal status codes
   - Adapt to custom severity levels and status codes

3. **Continuous Monitoring**: Monitor log files for new entries, extract important information, and batch for LLM analysis.

4. **Anomaly Detection**: LLM analyzes batched entries to identify anomalies, errors, and security concerns.

5. **Notifications**: Critical analysis results are posted to Slack (if enabled). 