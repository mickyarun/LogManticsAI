"""
LogManticsAI
Copyright (C) 2024 LogManticsAI

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>
"""

"""
Command-line interface for LogAI setup.
Handles interactive prompts for initial configuration and setup.
"""

import os
import json
import logging
import click
import yaml
import glob  # Add glob import for wildcard path support
from typing import List, Dict, Any, Tuple, Optional
from . import setup_tool
from . import agno_utils
from .config.config_loader import ensure_config_dir, save_yaml_config, get_config_file_path

logger = logging.getLogger(__name__)

# Available LLM models
SUPPORTED_MODELS = [
    "gpt-3.5-turbo",
    "gpt-4",
    "claude-2",
    "claude-3-opus-20240229",
    "claude-3-sonnet-20240229"
]

# Default prompt templates
DEFAULT_PROMPTS = {
    'anomaly_detection': """Analyze these log entries for anomalies, focusing on:
1. Error patterns and their severity
2. Unusual timing or performance issues
3. Security-related concerns
4. System state changes

Log entries:
{log_entries}

Please identify any anomalies and explain their potential impact.""",
    
    'key_importance': """Given these sample JSON log entries:
{sample_entries}

Which keys are most important for:
1. Analyzing application behavior
2. Identifying errors and warnings
3. Detecting performance issues
4. Monitoring security anomalies

Please list the key names and explain their significance."""
}

class LogFileValidator:
    """Validates and analyzes log files."""
    
    @staticmethod
    def validate_json_line(line: str) -> Tuple[bool, Optional[Dict]]:
        """Validates a single line of JSON."""
        try:
            data = json.loads(line.strip())
            return True, data
        except json.JSONDecodeError:
            return False, None
    
    @staticmethod
    def analyze_log_file(path: str, sample_size: int = 10) -> Tuple[bool, List[Dict], str]:
        """Analyzes a log file for JSON validity and structure."""
        try:
            valid_lines = []
            with open(path, 'r') as f:
                for i, line in enumerate(f):
                    if i >= sample_size:
                        break
                    is_valid, data = LogFileValidator.validate_json_line(line)
                    if not is_valid:
                        return False, [], f"Invalid JSON at line {i + 1}"
                    valid_lines.append(data)
            return True, valid_lines, "Valid JSON log file"
        except Exception as e:
            return False, [], str(e)

def validate_log_paths(log_files: List[str]) -> List[str]:
    """
    Validates the provided log file paths.
    Supports wildcard patterns using glob.
    Returns a list of valid log file paths.
    """
    valid_files = []
    for pattern in log_files:
        # Expand user directory if present
        expanded_pattern = os.path.expanduser(pattern)
        
        # Handle glob patterns
        matched_files = glob.glob(expanded_pattern)
        
        if not matched_files:
            click.echo(f"⚠️  No files found matching pattern: {pattern}")
            continue
            
        click.echo(f"Found {len(matched_files)} files matching: {pattern}")
        
        # Process each matched file
        for file_path in matched_files:
            # Skip if not a file
            if not os.path.isfile(file_path):
                click.echo(f"⚠️  Not a file: {file_path}")
                continue
                
            # Try to read the first line to verify JSON format
            try:
                with open(file_path, 'r') as f:
                    first_line = f.readline().strip()
                    json.loads(first_line)  # Try to parse as JSON
                valid_files.append(file_path)
                click.echo(f"✅ Validated: {file_path}")
            except json.JSONDecodeError:
                click.echo(f"⚠️  Not a valid JSON log file: {file_path}")
            except Exception as e:
                click.echo(f"⚠️  Error reading {file_path}: {str(e)}")
    
    return valid_files

@click.command()
@click.option('--model', help='LLM model to use (e.g., gpt-4, claude-3-sonnet)')
@click.option('--provider', type=click.Choice(['OPENAI', 'ANTHROPIC', 'GOOGLE', 'MISTRAL', 'GROQ', 'OLLAMA'],
              case_sensitive=False), help='LLM provider')
@click.option('--log-paths', help='Paths to JSON log files to analyze (supports glob patterns like *.json)')
@click.option('--api-key', hide_input=True, help='API key for the LLM provider')
@click.option('--slack/--no-slack', default=None, help='Configure Slack integration')
@click.option('--critical-levels', multiple=True, help='Custom critical log levels to monitor')
@click.option('--normal-status-codes', type=int, multiple=True, help='Custom normal status codes to ignore')
@click.option('--custom-fields/--no-custom-fields', default=False, help='Configure custom log field mappings')
@click.option('--non-interactive', is_flag=True, default=False, help='Run setup in non-interactive mode (requires --model, --api-key, and --log-paths)')
def setup(model: str, provider: str, log_paths: str, api_key: str, slack: bool,
          critical_levels: List[str], normal_status_codes: List[int], custom_fields: bool, non_interactive: bool = False):
    """Set up and configure the LogManticsAI tool
    
    Log paths can include wildcard patterns (e.g., /var/log/*.json) to match multiple files.
    All matched files will be validated to ensure they contain valid JSON log entries.
    """
    try:
        # Create configuration directory if it doesn't exist
        config_dir = ensure_config_dir()
        logger.info(f"Using configuration directory: {config_dir}")
        
        # Validate required parameters for non-interactive mode
        if non_interactive:
            if model is None or api_key is None or log_paths is None:
                click.echo("❌ Error: Non-interactive mode requires --model, --api-key, and --log-paths")
                return
            
            # Set defaults for optional parameters in non-interactive mode
            if provider is None:
                provider = 'OPENAI'
                click.echo(f"Using default provider: {provider}")
            
            if slack is None:
                slack = False
        
        # Check for existing configuration FIRST, before all other prompts
        config_file = get_config_file_path('config')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    existing_config = yaml.safe_load(f)
                if existing_config:
                    click.echo("\n⚠️  Existing configuration found!")
                    
                    if not non_interactive:
                        click.echo("\nCurrent Configuration:")
                        
                        # Don't show API key in display
                        display_config = existing_config.copy()
                        if 'llm_api_key' in display_config:
                            display_config['llm_api_key'] = '********'
                        click.echo(json.dumps(display_config, indent=2))
                        
                        if not click.confirm("\nDo you want to overwrite the existing configuration?", default=False):
                            click.echo("Setup aborted. Your existing configuration remains unchanged.")
                            return
                    else:
                        click.echo("Overwriting existing configuration in non-interactive mode.")
                        
                    click.echo("\nProceeding with new configuration setup...")
            except Exception as e:
                logger.warning(f"Failed to load existing configuration: {e}")
                if not non_interactive and not click.confirm("\nExisting configuration file found but could not be read. Do you want to proceed and overwrite it?", default=False):
                    click.echo("Setup aborted. Your existing configuration remains unchanged.")
                    return
                click.echo("\nProceeding with new configuration setup...")
        
        # Now prompt for all values if they weren't provided via command-line options
        if model is None:
            model = click.prompt('Enter the LLM model to use', default='gpt-4')
        
        if provider is None:
            provider = click.prompt('Enter the LLM provider', 
                                    type=click.Choice(['OPENAI', 'ANTHROPIC', 'GOOGLE', 'MISTRAL', 'GROQ', 'OLLAMA'],
                                                      case_sensitive=False),
                                    default='OPENAI')
        
        if log_paths is None:
            click.echo("\nLog paths can include wildcards (e.g., /var/log/*.json, /path/to/logs/*-2024*.json)")
            log_paths = click.prompt('Enter the paths to JSON log files (space-separated)')
        
        if api_key is None:
            api_key = click.prompt('Enter your LLM API key (will be stored securely)', hide_input=True)
        
        # For Click flags, None means it wasn't specified (using the flag's default)
        if slack is None:
            slack = click.confirm('Would you like to configure Slack notifications?', default=True)
        
        # Split log paths into a list
        log_files = log_paths.split()
        
        # Validate log files
        valid_files = validate_log_paths(log_files)
        
        if not valid_files:
            if non_interactive:
                # In non-interactive mode, just warn but continue with the configuration
                # This allows setting up patterns that might match files in the future
                click.echo("⚠️ Warning: No valid log files found for the provided patterns")
                click.echo("The configuration will be saved, but you may need to add valid log files later")
                # Create a placeholder for log_files in the config
                config_data['log_files'] = {}
                config_data['log_patterns'] = log_files  # Store the patterns for future use
            else:
                logger.error("No valid log files provided")
                return
        
        # Create initial configuration
        config_data = {
            'llm_model': model,
            'llm_provider': provider,
            # Store API key reference, not the actual key
            'api_key_secured': 'true',  
            'log_files': {},
            'slack_enabled': 'false',  # Default to disabled
            'prompts': DEFAULT_PROMPTS,
            'anomaly_detection': {}
        }
        
        # Set up default critical levels and status codes
        default_critical_levels = ["WARNING", "ERROR", "CRITICAL"]
        default_normal_codes = [0, 200]
        
        # Use custom values if provided
        if critical_levels:
            default_critical_levels = list(critical_levels)
        if normal_status_codes:
            default_normal_codes = list(normal_status_codes)
        
        # Test the API key
        click.echo("Testing API key...")
        try:
            agno_utils.create_model(provider, api_key, model)
            click.echo("✅ API key is valid")
            
            # Store API key securely in keyring
            try:
                import keyring
                keyring.set_password("LogManticsAI", "llm_api_key", api_key)
                click.echo("✅ API key stored securely")
                config_data['api_key_secured'] = 'true'
            except Exception as e:
                click.echo(f"⚠️ Failed to store API key securely: {e}")
                click.echo("Storing API key in configuration file")
                config_data['llm_api_key'] = api_key  # Fallback to store in config
                config_data['api_key_secured'] = 'false'
        except Exception as e:
            click.echo(f"❌ API key test failed: {str(e)}")
            if not non_interactive and not click.confirm("Do you want to continue anyway?", default=False):
                click.echo("Setup aborted.")
                return
            elif non_interactive:
                click.echo("Continuing with failed API key in non-interactive mode.")
                
            # Still try to store API key securely
            try:
                import keyring
                keyring.set_password("LogManticsAI", "llm_api_key", api_key)
                click.echo("API key stored securely despite test failure")
                config_data['api_key_secured'] = 'true'
            except Exception as e:
                click.echo(f"Failed to store API key securely: {e}")
                click.echo("Storing API key in configuration file")
                config_data['llm_api_key'] = api_key  # Fallback
                config_data['api_key_secured'] = 'false'
                
        # Configure custom field mappings if requested
        field_mappings = {}
        if custom_fields:
            if non_interactive:
                # In non-interactive mode, just use default field mappings
                click.echo("Using default field mappings in non-interactive mode")
            else:
                field_mappings = prompt_for_custom_field_mapping()
                if field_mappings:
                    config_data['field_mappings'] = field_mappings
                    click.echo("✅ Custom field mappings configured")
        elif not non_interactive and click.confirm("\nWould you like to configure custom field mappings?", default=False):
            field_mappings = prompt_for_custom_field_mapping()
            if field_mappings:
                config_data['field_mappings'] = field_mappings
                click.echo("✅ Custom field mappings configured")
        
        # Configure anomaly detection thresholds
        if not non_interactive and click.confirm("\nWould you like to configure anomaly detection thresholds?", default=True):
            thresholds = prompt_for_anomaly_thresholds()
            config_data['anomaly_detection'] = thresholds
            click.echo("✅ Anomaly detection thresholds configured")
        else:
            # Set default thresholds in non-interactive mode
            config_data['anomaly_detection'] = {
                'error_rate': 5.0,
                'response_time_ms': 1000,
                'batch_size': 100,
                'analysis_interval_sec': 300
            }
            if non_interactive:
                click.echo("Using default anomaly detection thresholds in non-interactive mode")
        
        # Configure Slack if requested
        if slack and not non_interactive:
            click.echo("\nConfiguring Slack integration...")
            slack_token = click.prompt("Enter your Slack Bot Token (xoxb-...)", hide_input=True)
            slack_channel = click.prompt("Enter the Slack channel name (e.g., LogManticsAI-alerts or #LogManticsAI-alerts)")
            
            # Ensure channel starts with # for public channels
            if not slack_channel.startswith('#') and not slack_channel.startswith('C'):
                click.echo(f"Adding # prefix to channel name: #{slack_channel}")
                slack_channel = f"#{slack_channel}"
            
            # Test Slack configuration
            click.echo("Testing Slack configuration...")
            try:
                from .slack_utils import validate_slack_config
                if validate_slack_config(slack_token, slack_channel):
                    click.echo("✅ Slack configuration is valid")
                    config_data['slack_token'] = slack_token
                    config_data['slack_channel'] = slack_channel
                    config_data['slack_enabled'] = 'true'
                else:
                    click.echo("❌ Slack configuration test failed. Integration will be disabled.")
                    
                    # Show troubleshooting tips
                    click.echo("\nTroubleshooting tips:")
                    click.echo("1. Verify your Slack Bot Token starts with 'xoxb-'")
                    click.echo("2. Make sure the bot has been added to the specified channel")
                    click.echo("3. For private channels, use the channel ID instead of name")
                    click.echo("4. Check if the bot has the necessary permissions (chat:write, chat:write.public)")
                    
                    if click.confirm("Do you want to save the Slack configuration anyway? You can fix it later.", default=True):
                        # Store configuration but keep disabled
                        config_data['slack_token'] = slack_token
                        config_data['slack_channel'] = slack_channel
                        config_data['slack_enabled'] = 'false'
                        click.echo("Slack configuration saved but disabled. You can test it again with 'LogManticsAI slack-test'.")
            except Exception as e:
                click.echo(f"❌ Error testing Slack configuration: {str(e)}")
                
                # Show error details and troubleshooting tips
                click.echo("\nError details and troubleshooting tips:")
                click.echo(f"- Error message: {str(e)}")
                click.echo("- Verify your Slack Bot Token starts with 'xoxb-'")
                click.echo("- Make sure the bot has been added to the specified channel")
                click.echo("- The Slack API may be temporarily unavailable")
                
                if click.confirm("Do you want to save the Slack configuration anyway? You can fix it later.", default=True):
                    # Store configuration but keep disabled
                    config_data['slack_token'] = slack_token
                    config_data['slack_channel'] = slack_channel
                    config_data['slack_enabled'] = 'false'
                    click.echo("Slack configuration saved but disabled. You can test it again with 'LogManticsAI slack-test'.")
        elif slack and non_interactive:
            # In non-interactive mode with --slack flag, we don't have the token/channel
            click.echo("Slack integration enabled in non-interactive mode, but no token/channel provided.")
            click.echo("You'll need to configure Slack separately using 'LogManticsAI-config' commands.")
            config_data['slack_enabled'] = 'false'
        
        # Analyze each log file
        if valid_files:
            for log_file in valid_files:
                click.echo(f"\nAnalyzing {log_file}...")
                
                # Analyze log structure and identify important keys
                sample_lines, important_keys = setup_tool.initial_log_analysis_and_key_id(log_file, config_data)
                
                if sample_lines and important_keys:
                    click.echo(f"✅ Found {len(important_keys)} important keys: {', '.join(important_keys)}")
                    config_data['log_files'][log_file] = {
                        'important_keys': important_keys,
                        'critical_levels': default_critical_levels,
                        'normal_status_codes': default_normal_codes
                    }
                    
                    # Apply field mappings if configured
                    if field_mappings:
                        config_data['log_files'][log_file]['field_mappings'] = field_mappings
                else:
                    click.echo(f"⚠️ Failed to analyze {log_file}")
        elif non_interactive:
            # In non-interactive mode with no valid files, we still want to save the configuration
            # with the default settings for future use
            click.echo("Skipping log file analysis in non-interactive mode with no valid files")
            config_data['default_critical_levels'] = default_critical_levels
            config_data['default_normal_status_codes'] = default_normal_codes
            if field_mappings:
                config_data['default_field_mappings'] = field_mappings
        
        # Save the configuration
        if save_yaml_config('config', config_data):
            click.echo(f"\nConfiguration saved successfully to {config_dir}")
            
            # Display configuration summary
            click.echo("\nConfiguration Summary:")
            click.echo(f"- LLM Model: {model} ({provider})")
            click.echo(f"- API Key: {'Stored securely in keyring' if config_data.get('api_key_secured') == 'true' else 'Stored in configuration file'}")
            
            if valid_files:
                click.echo(f"- Monitored Log Files: {len(valid_files)}")
            else:
                click.echo(f"- Log Patterns: {', '.join(log_files)}")
                
            click.echo(f"- Critical Levels: {', '.join(default_critical_levels)}")
            click.echo(f"- Normal Status Codes: {', '.join(map(str, default_normal_codes))}")
            if field_mappings:
                click.echo("- Custom Field Mappings:")
                for std, custom in field_mappings.items():
                    click.echo(f"  • {std} → {custom}")
            if 'anomaly_detection' in config_data:
                click.echo("- Anomaly Detection Thresholds:")
                for key, value in config_data['anomaly_detection'].items():
                    click.echo(f"  • {key}: {value}")
            click.echo(f"- Slack Integration: {'Enabled' if config_data['slack_enabled'] == 'true' else 'Disabled'}")
            
            click.echo("\n✨ Setup complete! You can now start monitoring with 'LogManticsAI-monitor'")
        else:
            click.echo("❌ Failed to save configuration")
            
    except Exception as e:
        logger.error(f"Setup failed: {str(e)}")
        click.echo("❌ Setup failed. Please check the logs for details.")
        raise

def prompt_for_custom_field_mapping() -> Dict[str, str]:
    """Prompts user for custom log field mappings."""
    click.echo("\nCustom field mapping setup (press Enter to skip):")
    mappings = {}
    standard_fields = ['timestamp', 'level', 'message', 'error']
    
    for field in standard_fields:
        custom = click.prompt(
            f"Custom field name for '{field}' in your logs",
            default='',
            show_default=False
        )
        if custom:
            mappings[field] = custom
    
    return mappings

def prompt_for_anomaly_thresholds() -> Dict[str, Any]:
    """Prompts user for anomaly detection thresholds."""
    click.echo("\nAnomaly detection threshold setup:")
    
    thresholds = {
        'error_rate': click.prompt(
            'Maximum error rate per minute before alerting (e.g., 5)',
            type=float,
            default=5.0
        ),
        'response_time_ms': click.prompt(
            'Response time threshold in ms (e.g., 1000)',
            type=int,
            default=1000
        ),
        'batch_size': click.prompt(
            'Number of logs to analyze in each batch',
            type=int,
            default=100
        ),
        'analysis_interval_sec': click.prompt(
            'Analysis interval in seconds',
            type=int,
            default=300
        )
    }
    
    return thresholds

if __name__ == '__main__':
    setup() 