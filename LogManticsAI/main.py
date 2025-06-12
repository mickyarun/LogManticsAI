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
Main CLI entry points for the LogManticsAI tool.
Uses Click to define commands for the command-line interface.
"""

import click
import os
import logging
import sys
import warnings
import json
from typing import Dict, Any, Optional, List

from .config.config_loader import load_yaml_config, save_yaml_config
from . import setup_tool
from . import monitoring
from . import config as LogManticsAI_config
from . import agno_utils
from . import cli_setup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Set specific loggers to a higher level by default
logging.getLogger('slack_sdk').setLevel(logging.WARNING)
logging.getLogger('watchdog').setLevel(logging.WARNING)

def configure_debug_logging(debug):
    """Configure logging based on debug flag"""
    if debug:
        # Set root logger to DEBUG
        logging.getLogger().setLevel(logging.DEBUG)
        # Set relevant module loggers to DEBUG
        logging.getLogger('LogManticsAI').setLevel(logging.DEBUG)
        logging.getLogger('LogManticsAI.slack_utils').setLevel(logging.DEBUG)
        logging.getLogger('slack_sdk').setLevel(logging.DEBUG)
        logger.info("Debug logging enabled")
    else:
        # Keep default levels
        logging.getLogger().setLevel(logging.INFO)

@click.group()
def cli():
    """LogManticsAI - LLM-Powered Log Analysis Tool"""
    pass

@cli.command(name="init")
@click.option('--model', prompt='Enter the LLM model to use', 
              default='gpt-4', help='LLM model to use (e.g., gpt-4, claude-3-sonnet)')
@click.option('--provider', type=click.Choice(['OPENAI', 'ANTHROPIC', 'GOOGLE', 'MISTRAL', 'GROQ', 'OLLAMA'], 
              case_sensitive=False), default='OPENAI', help='LLM provider')
@click.option('--log-file', prompt='Enter the absolute path to the JSON log file',
              type=click.Path(exists=True, dir_okay=False, resolve_path=True),
              help='Path to the JSON log file to analyze')
@click.option('--api-key', prompt='Enter your LLM API key (will be stored securely)',
              hide_input=True, help='API key for the LLM provider')
@click.option('--slack/--no-slack', default=False, help='Configure Slack integration')
def tool_setup_command(model, provider, log_file, api_key, slack):
    """[DEPRECATED] Initialize and configure the LogManticsAI tool. Use 'setup' command instead."""
    warnings.warn("The 'init' command is deprecated. Please use 'LogManticsAI setup' instead.", DeprecationWarning)
    click.echo("⚠️  This command is deprecated. Please use 'LogManticsAI setup' instead.")
    
    try:
        click.echo(f"Initializing LogManticsAI...\nModel: {model}\nProvider: {provider}\nLog file: {log_file}")
        
        # Ensure config directory exists
        LogManticsAI_config.ensure_config_dir()
        
        # Create initial configuration
        config_data = {
            'llm_model': model,
            'llm_provider': provider,
            'log_files': {log_file: {}},
        }
        
        # Quick test of model creation
        agno_utils.create_model(provider, api_key, model)
        click.echo("✅ API key is valid")
        
        # Optionally configure Slack
        if slack or click.confirm("Would you like to configure Slack integration to receive analysis notifications?", default=False):
            click.echo("\nConfiguring Slack integration...")
            slack_token = click.prompt("Enter your Slack Bot Token (xoxb-...)", hide_input=True)
            slack_channel = click.prompt("Enter the Slack channel to post to (e.g., #LogManticsAI-alerts)")
            
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
                    if click.confirm("Do you want to save the Slack configuration anyway?", default=False):
                        config_data['slack_token'] = slack_token
                        config_data['slack_channel'] = slack_channel
                        config_data['slack_enabled'] = 'false'
            except Exception as e:
                click.echo(f"❌ Error testing Slack configuration: {str(e)}")
                config_data['slack_enabled'] = 'false'
        
        # Save the configuration
        LogManticsAI_config.save_config(config_data)
        click.echo(f"Configuration saved to {LogManticsAI_config.get_config_file_path()}")
        
        # Save the API key securely
        LogManticsAI_config.save_api_key(api_key)
        click.echo("API key saved securely.")
        
        # Proceed with log analysis (kept simple for now)
        click.echo(f"\nAnalyzing log file {log_file}...")
        
        # TODO: Need to add the actual log analysis functionality
        
        click.echo("\nSetup complete! You can now run 'LogManticsAI-monitor' to start monitoring your logs.")
        
    except Exception as e:
        click.echo(f"❌ Error during setup: {str(e)}")
        if os.environ.get('DEBUG', '').lower() == 'true':
            import traceback
            click.echo(traceback.format_exc())

@cli.command(name="monitor")
@click.option('--config-file', type=click.Path(exists=True, dir_okay=False),
              default=None, help='Custom path to config file')
@click.option('--debug', is_flag=True, default=False, help='Enable debug logging')
def tail_and_analyze_command(config_file, debug):
    """
    Start continuous log monitoring and analysis.
    
    This command will:
    - Tail the configured log file
    - Process new entries as they appear
    - Use the LLM to detect anomalies
    - Save analysis results
    
    Press Ctrl+C to stop monitoring.
    """
    # Configure debug logging if enabled
    configure_debug_logging(debug)
    
    # Load configuration (either from default location or custom path)
    if config_file:
        # TODO: Implement loading from custom config file
        pass
        
    config_data = LogManticsAI_config.load_yaml_config('config')
    if not config_data:
        click.echo("Error: Configuration not found. Please run 'LogManticsAI setup' first.")
        return
    
    log_files = config_data.get('log_files', {})
    if not log_files:
        click.echo("Error: No log files configured. Please run 'LogManticsAI setup' first.")
        return
    
    click.echo(f"Found {len(log_files)} configured log files:")
    for log_file_path, file_config in log_files.items():
        important_keys = file_config.get('important_keys', [])
        click.echo(f"\n📄 {log_file_path}")
        click.echo(f"   Important keys ({len(important_keys)}): {', '.join(important_keys)}")
        click.echo(f"   Critical levels: {', '.join(file_config.get('critical_levels', []))}")
    
    # Display Slack status if configured
    if config_data.get('slack_enabled', '').lower() == 'true':
        click.echo(f"\nSlack notifications enabled for channel: {config_data.get('slack_channel')}")
    else:
        click.echo("\nSlack notifications disabled")
        
    click.echo("\nPress Ctrl+C to stop monitoring")
    
    try:
        # Start the monitoring loop for all configured log files
        monitoring.start_monitoring(log_files, config_data)
    except KeyboardInterrupt:
        click.echo("\nMonitoring stopped by user")
    except Exception as e:
        click.echo(f"\nError during monitoring: {e}")

@cli.command('config')
@click.option('--show', is_flag=True, help='Show current configuration')
@click.option('--add-log-file', help='Add a new log file to monitor')
@click.option('--remove-log-file', help='Remove a log file from monitoring')
@click.option('--list-log-files', is_flag=True, help='List all monitored log files')
@click.option('--reset', is_flag=True, help='Reset all configuration')
@click.option('--slack-enable', is_flag=True, help='Enable Slack notifications')
@click.option('--slack-disable', is_flag=True, help='Disable Slack notifications')
@click.option('--slack-channel', help='Update Slack channel')
@click.option('--slack-token', help='Update Slack token')
@click.option('--batch-size', type=int, help='Set the number of logs to analyze in each batch')
@click.option('--analysis-interval', type=int, help='Set analysis interval in seconds')
@click.option('--error-rate-threshold', type=float, help='Set maximum error rate per minute before alerting')
@click.option('--response-time-threshold', type=int, help='Set response time threshold in milliseconds')
@click.option('--process-existing-logs', type=bool, help='Enable/disable processing of existing logs on startup')
def config_command(show, add_log_file, remove_log_file, list_log_files, reset,
                  slack_enable, slack_disable, slack_channel, slack_token,
                  batch_size, analysis_interval, error_rate_threshold,
                  response_time_threshold, process_existing_logs):
    """Manage LogManticsAI configuration"""
    try:
        # Import necessary modules
        from .config.config_loader import save_yaml_config
        
        if show:
            # Load and display current configuration
            config = LogManticsAI_config.load_yaml_config('config')
            if config:
                click.echo("\nCurrent Configuration:")
                click.echo(json.dumps(config, indent=2))
            else:
                click.echo("No configuration found.")
            return

        if reset:
            # Reset configuration
            if click.confirm("Are you sure you want to reset all configuration?"):
                LogManticsAI_config.reset_config()
                click.echo("Configuration reset successfully.")
            return

        if list_log_files:
            # List monitored log files
            config = LogManticsAI_config.load_yaml_config('config')
            if config and 'log_files' in config:
                click.echo("\nMonitored Log Files:")
                for log_file in config['log_files']:
                    click.echo(f"- {log_file}")
            else:
                click.echo("No log files configured.")
            return

        if add_log_file:
            # Add new log file
            if not os.path.exists(add_log_file):
                click.echo(f"Error: File {add_log_file} does not exist.")
                return
            config = LogManticsAI_config.load_yaml_config('config') or {}
            if 'log_files' not in config:
                config['log_files'] = {}
            config['log_files'][add_log_file] = {
                'critical_levels': ["WARNING", "ERROR", "CRITICAL"],
                'normal_status_codes': [0, 200]
            }
            save_yaml_config('config', config)
            click.echo(f"Added {add_log_file} to monitored files.")
            return

        if remove_log_file:
            # Remove log file
            config = LogManticsAI_config.load_yaml_config('config')
            if config and 'log_files' in config:
                if remove_log_file in config['log_files']:
                    del config['log_files'][remove_log_file]
                    save_yaml_config('config', config)
                    click.echo(f"Removed {remove_log_file} from monitored files.")
                else:
                    click.echo(f"Error: {remove_log_file} not found in configuration.")
            return

        # Handle Slack configuration
        if any([slack_enable, slack_disable, slack_channel, slack_token]):
            config = LogManticsAI_config.load_yaml_config('config') or {}
            
            if slack_enable:
                config['slack_enabled'] = 'true'
                click.echo("Slack notifications enabled.")
            
            if slack_disable:
                config['slack_enabled'] = 'false'
                click.echo("Slack notifications disabled.")
            
            if slack_channel:
                config['slack_channel'] = slack_channel
                click.echo(f"Slack channel updated to {slack_channel}")
            
            if slack_token:
                config['slack_token'] = slack_token
                click.echo("Slack token updated.")
            
            save_yaml_config('config', config)
            return
            
        # Handle anomaly detection configuration
        if any([batch_size, analysis_interval, error_rate_threshold, 
                response_time_threshold, process_existing_logs is not None]):
            config = LogManticsAI_config.load_yaml_config('config') or {}
            
            # Ensure anomaly_detection section exists
            if 'anomaly_detection' not in config:
                config['anomaly_detection'] = {}
            
            if batch_size is not None:
                config['anomaly_detection']['batch_size'] = batch_size
                click.echo(f"Batch size updated to {batch_size} logs per batch")
            
            if analysis_interval is not None:
                config['anomaly_detection']['analysis_interval_sec'] = analysis_interval
                click.echo(f"Analysis interval updated to {analysis_interval} seconds")
            
            if error_rate_threshold is not None:
                config['anomaly_detection']['error_rate'] = error_rate_threshold
                click.echo(f"Error rate threshold updated to {error_rate_threshold} errors/minute")
            
            if response_time_threshold is not None:
                config['anomaly_detection']['response_time_ms'] = response_time_threshold
                click.echo(f"Response time threshold updated to {response_time_threshold} ms")
            
            if process_existing_logs is not None:
                config['anomaly_detection']['process_existing_logs'] = process_existing_logs
                status = "enabled" if process_existing_logs else "disabled"
                click.echo(f"Processing existing logs on startup {status}")
            
            save_yaml_config('config', config)
            return

    except Exception as e:
        click.echo(f"Error: {str(e)}")

@cli.command('slack-test')
@click.option('--debug', is_flag=True, default=False, help='Enable debug logging')
@click.option('--channel', type=str, help='Override the channel to test with')
@click.option('--token', type=str, help='Override the Slack token to test with')
def test_slack_command(debug, channel, token):
    """
    Test Slack integration by sending a test message.
    
    This command loads your current configuration and sends
    a test message to the configured Slack channel to verify
    that the integration is working properly.
    """
    # Configure debug logging if enabled
    configure_debug_logging(debug)
    
    # Import necessary modules
    from .config.config_loader import save_yaml_config
    
    # Load configuration
    config = LogManticsAI_config.load_yaml_config('config')
    if not config:
        click.echo("Error: Configuration not found. Please run 'LogManticsAI setup' first.")
        return
    
    # Use overrides if provided, otherwise use config values
    slack_channel = channel or config.get('slack_channel')
    slack_token = token or config.get('slack_token')
    
    # Check if Slack is configured
    if not slack_token or not slack_channel:
        click.echo("Error: Slack is not fully configured. Run 'LogManticsAI setup' to configure Slack.")
        
        # Prompt for values if missing
        if not slack_token:
            slack_token = click.prompt("Enter your Slack Bot Token (xoxb-...)", hide_input=True)
        if not slack_channel:
            slack_channel = click.prompt("Enter the Slack channel name (e.g., LogManticsAI-alerts or #LogManticsAI-alerts)")
    
    # Ensure channel name has # prefix for public channels
    if slack_channel and not slack_channel.startswith('#') and not slack_channel.startswith('C'):
        click.echo(f"Note: Adding # prefix to channel name: #{slack_channel}")
        slack_channel = f"#{slack_channel}"
    
    click.echo(f"Testing Slack integration with channel: {slack_channel}")
    
    try:
        from .slack_utils import send_slack_message
        test_message = (
            "*LogManticsAI Slack Test Message*\n\n"
            "✅ This is a test message from LogManticsAI to verify your Slack integration.\n\n"
            "If you can see this message, your Slack integration is working correctly!"
        )
        
        success = send_slack_message(slack_token, slack_channel, test_message)
        
        if success:
            click.echo("✅ Slack configuration is valid!")
            click.echo("Successfully sent a test message.")
            
            # If integration is disabled but test worked, ask if user wants to enable it
            if config.get('slack_enabled') != 'true':
                click.echo("\nNote: Slack integration is currently disabled in your configuration.")
                if click.confirm("Would you like to enable Slack notifications?", default=True):
                    config['slack_enabled'] = 'true'
                    
                    # Save updated token/channel if they were provided via parameters
                    if channel:
                        config['slack_channel'] = channel
                    if token:
                        config['slack_token'] = token
                        
                    save_yaml_config('config', config)
                    click.echo("✅ Slack notifications have been enabled.")
                    
            # If channel or token were overridden and working, ask to save them
            elif (channel or token) and click.confirm("Would you like to save this Slack configuration?", default=True):
                if channel:
                    config['slack_channel'] = channel
                if token:
                    config['slack_token'] = token
                save_yaml_config('config', config)
                click.echo("✅ Slack configuration has been updated.")
        else:
            click.echo("❌ Slack configuration test failed.")
            click.echo("Could not send message to the specified channel.")
            
            if debug:
                click.echo("\nTroubleshooting tips:")
                click.echo("1. Verify your Slack Bot Token starts with 'xoxb-'")
                click.echo("2. Make sure the bot has been added to the specified channel")
                click.echo("3. For public channels, make sure the channel name is correct (with or without #)")
                click.echo("4. For private channels, use the channel ID instead of name")
                click.echo("5. Check if the bot has the necessary permissions (chat:write, chat:write.public)")
            else:
                click.echo("Run again with --debug for more detailed logs and troubleshooting tips.")
    
    except ImportError:
        click.echo("❌ Error: Slack SDK not installed. Run 'pip install slack-sdk'.")
    except Exception as e:
        click.echo(f"❌ Unexpected error: {str(e)}")
        if debug:
            import traceback
            click.echo("\nDetailed error information:")
            click.echo(traceback.format_exc())

# Add the new setup command
cli.add_command(cli_setup.setup)

# Register all CLI commands
tool_setup_command = cli.commands['init']
tail_and_analyze_command = cli.commands['monitor']

if __name__ == '__main__':
    # This allows direct script execution for development
    cli() 