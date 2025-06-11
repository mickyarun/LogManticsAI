#!/usr/bin/env python3
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

Demo script for LogAI.
This script demonstrates how to use LogAI programmatically to analyze logs.
"""

import os
import argparse
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Any
import sys

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("LogManticsAI-demo")

# Import LogAI modules
from LogManticsAI.agno_utils import create_model, create_log_analysis_agent
from LogManticsAI.setup_tool import analyze_log_structure
from LogManticsAI.llm_utils import get_important_keys_from_llm, send_logs_for_anomaly_detection

class LogFileConfig:
    """Configuration for a single log file"""
    def __init__(self, path: str, critical_levels: List[str] = None, normal_status_codes: List[int] = None):
        self.path = path
        self.critical_levels = critical_levels or ["WARNING", "ERROR", "CRITICAL"]
        self.normal_status_codes = normal_status_codes or [0, 200]
        self.important_keys = []
        self.sample_entries = []

def setup_demo(log_configs: Dict[str, LogFileConfig], api_key: str, model: str = "gpt-3.5-turbo", 
              provider: str = "OPENAI", slack_config: Dict[str, str] = None):
    """Set up the demo by analyzing multiple log files"""
    logger.info(f"Starting LogAI demo with {len(log_configs)} log files")
    
    llm_config = {
        'llm_model': model,
        'llm_provider': provider,
        'llm_api_key': api_key
    }

    # Add Slack configuration if provided
    if slack_config:
        llm_config.update({
            'slack_enabled': 'true',
            'slack_token': slack_config.get('slack_token', ''),
            'slack_channel': slack_config.get('slack_channel', '')
        })
    
    # Analyze each log file
    for path, config in log_configs.items():
        logger.info(f"\nAnalyzing {path}...")
        
        # 1. Analyze log structure
        sample_entries, common_keys = analyze_log_structure(path)
        
        if not sample_entries or not common_keys:
            logger.error(f"Failed to analyze log structure for {path}. Skipping.")
            continue
        
        logger.info(f"Found {len(common_keys)} common keys: {', '.join(common_keys)}")
        
        # 2. Use LLM to identify important keys
        important_keys = get_important_keys_from_llm(sample_entries, llm_config)
        
        if not important_keys:
            logger.warning(f"Couldn't get important keys from LLM for {path}. Using common keys instead.")
            important_keys = list(common_keys)
        
        logger.info(f"Identified {len(important_keys)} important keys: {', '.join(important_keys)}")
        
        # Store results in config
        config.important_keys = important_keys
        config.sample_entries = sample_entries

    return log_configs

def analyze_batch(log_entries: List[Dict], config: LogFileConfig, llm_config: Dict):
    """Analyze a batch of log entries using the LLM"""
    # Process the logs to focus on important keys and filter by level/status
    processed_entries = []
    filtered_count = 0
    total_count = len(log_entries)
    
    for entry in log_entries:
        # Filter based on configured levels and status codes
        level = entry.get("level", "")
        status_code = entry.get("status_code", 200)
        
        if level in config.critical_levels or (status_code not in config.normal_status_codes):
            processed_entry = {key: entry[key] for key in config.important_keys if key in entry}
            # Always include core fields if available
            for key in ['timestamp', 'message', 'level', 'status_code']:
                if key not in processed_entry and key in entry:
                    processed_entry[key] = entry[key]
            processed_entry['_logai_source'] = os.path.basename(config.path)
            processed_entries.append(processed_entry)
        else:
            filtered_count += 1
    
    # Skip if no entries match the criteria
    if not processed_entries:
        logger.info(f"No critical logs to analyze in this batch from {config.path}. "
                   f"Filtered out {filtered_count}/{total_count} normal logs.")
        return
    
    logger.info(f"Analyzing {len(processed_entries)} critical logs from {config.path} "
                f"(filtered {filtered_count}/{total_count} normal logs)")
    
    # Send to LLM for analysis
    analysis = send_logs_for_anomaly_detection(processed_entries, llm_config)
    
    if analysis:
        logger.info(f"Analysis results for {config.path}:")
        print("\n" + "="*50)
        print(f"Log Analysis Results - {os.path.basename(config.path)}")
        print("="*50)
        print(analysis)
        print("="*50 + "\n")

        # Send to Slack if enabled
        if llm_config.get('slack_enabled') == 'true':
            try:
                from LogManticsAI.slack_utils import send_analysis_to_slack
                slack_config = {
                    'slack_token': llm_config.get('slack_token', ''),
                    'slack_channel': llm_config.get('slack_channel', '')
                }
                success = send_analysis_to_slack(analysis, processed_entries, slack_config, config.path)
                if success:
                    logger.info(f"Analysis for {config.path} posted to Slack successfully")
                else:
                    logger.warning(f"Failed to post analysis for {config.path} to Slack")
            except Exception as e:
                logger.error(f"Error sending Slack notification: {e}")
    else:
        logger.warning(f"No analysis results returned for {config.path}")

def run_demo(log_configs: Dict[str, LogFileConfig], api_key: str, model: str = "gpt-3.5-turbo", 
            provider: str = "OPENAI", slack_config: Dict[str, str] = None):
    """Run the complete LogAI demo"""
    # Set up demo
    log_configs = setup_demo(log_configs, api_key, model, provider, slack_config)
    
    llm_config = {
        'llm_model': model,
        'llm_provider': provider,
        'llm_api_key': api_key
    }

    # Add Slack configuration if provided
    if slack_config:
        llm_config.update({
            'slack_enabled': 'true',
            'slack_token': slack_config.get('slack_token', ''),
            'slack_channel': slack_config.get('slack_channel', '')
        })
    
    # For demo purposes, analyze sample entries in batches for each file
    batch_size = 10
    for path, config in log_configs.items():
        if not config.sample_entries:
            continue
            
        logger.info(f"\nAnalyzing {path}...")
        for i in range(0, len(config.sample_entries), batch_size):
            batch = config.sample_entries[i:i+batch_size]
            logger.info(f"Analyzing batch {i//batch_size + 1}/{(len(config.sample_entries) + batch_size - 1)//batch_size}")
            analyze_batch(batch, config, llm_config)
            
            # Don't continue with more batches unless user wants to
            if i + batch_size < len(config.sample_entries):
                choice = input(f"Continue to next batch for {os.path.basename(path)}? (y/n): ").strip().lower()
                if choice != 'y':
                    break

def monitor_log_files(log_configs: Dict[str, LogFileConfig], api_key: str, model: str = "gpt-3.5-turbo", 
                     provider: str = "OPENAI", interval: int = 60, slack_config: Dict[str, str] = None):
    """Monitor multiple log files for new entries"""
    # Set up demo
    log_configs = setup_demo(log_configs, api_key, model, provider, slack_config)
    
    llm_config = {
        'llm_model': model,
        'llm_provider': provider,
        'llm_api_key': api_key
    }

    # Add Slack configuration if provided
    if slack_config:
        llm_config.update({
            'slack_enabled': 'true',
            'slack_token': slack_config.get('slack_token', ''),
            'slack_channel': slack_config.get('slack_channel', '')
        })
    
    # Track file positions
    file_positions = {path: os.path.getsize(path) for path in log_configs.keys()}
    
    # Buffers for each file
    log_buffers = {path: [] for path in log_configs.keys()}
    last_analysis_time = time.time()
    
    logger.info(f"Starting to monitor {len(log_configs)} log files. Press Ctrl+C to stop.")
    
    try:
        while True:
            for path, config in log_configs.items():
                try:
                    current_size = os.path.getsize(path)
                    
                    if current_size > file_positions[path]:
                        with open(path, 'r') as f:
                            f.seek(file_positions[path])
                            new_lines = f.readlines()
                            
                            # Process new lines
                            for line in new_lines:
                                try:
                                    log_entry = json.loads(line.strip())
                                    log_buffers[path].append(log_entry)
                                except json.JSONDecodeError:
                                    logger.warning(f"Skipping invalid JSON in {path}: {line[:100]}...")
                            
                            file_positions[path] = f.tell()
                            
                            if new_lines:
                                logger.info(f"Read {len(new_lines)} new entries from {os.path.basename(path)}. "
                                          f"Buffer size: {len(log_buffers[path])}")
                                
                except Exception as e:
                    logger.error(f"Error reading {path}: {e}")
            
            # Check if it's time to analyze any buffers
            current_time = time.time()
            time_elapsed = (current_time - last_analysis_time) >= interval
            
            if time_elapsed:
                for path, buffer in log_buffers.items():
                    if buffer:
                        logger.info(f"Analyzing buffer of {len(buffer)} entries from {os.path.basename(path)}...")
                        analyze_batch(buffer, log_configs[path], llm_config)
                        log_buffers[path] = []
                last_analysis_time = current_time
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user")
        # Final analysis of remaining buffers
        for path, buffer in log_buffers.items():
            if buffer:
                logger.info(f"Final analysis of {len(buffer)} entries from {os.path.basename(path)}...")
                analyze_batch(buffer, log_configs[path], llm_config)

def test_slack_notification(slack_token: str, slack_channel: str):
    """Test Slack notification setup"""
    try:
        from LogManticsAI.slack_utils import send_analysis_to_slack
        
        test_message = {
            "type": "test",
            "message": "This is a test notification from LogAI demo script.",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        slack_config = {
            'slack_token': slack_token,
            'slack_channel': slack_channel
        }
        
        success = send_analysis_to_slack(
            "Test Analysis: LogAI demo script is working correctly.", 
            [test_message], 
            slack_config,
            "test.log"
        )
        
        if success:
            logger.info("Slack test notification sent successfully")
            return True
        else:
            logger.error("Failed to send Slack test notification")
            return False
            
    except Exception as e:
        logger.error(f"Error testing Slack notification: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='LogAI Demo')
    parser.add_argument('--log-paths', '-f', required=True, nargs='+', help='Paths to log files')
    parser.add_argument('--api-key', '-k', required=True, help='API key for the LLM provider')
    parser.add_argument('--model', '-m', default='gpt-3.5-turbo', help='LLM model to use')
    parser.add_argument('--provider', '-p', default='OPENAI', help='LLM provider (OPENAI, ANTHROPIC, etc.)')
    parser.add_argument('--monitor', action='store_true', help='Monitor log files for new entries')
    parser.add_argument('--interval', '-i', type=int, default=60, help='Analysis interval in seconds (for monitoring)')
    parser.add_argument('--critical-levels', '-l', nargs='+', help='Custom critical log levels to monitor')
    parser.add_argument('--normal-status-codes', '-s', type=int, nargs='+', help='Custom normal status codes to ignore')
    parser.add_argument('--slack-token', help='Slack bot token for notifications')
    parser.add_argument('--slack-channel', help='Slack channel for notifications')
    parser.add_argument('--test-slack', action='store_true', help='Test Slack notification setup')
    
    args = parser.parse_args()

    # Handle Slack configuration
    slack_config = None
    if args.slack_token and args.slack_channel:
        slack_config = {
            'slack_token': args.slack_token,
            'slack_channel': args.slack_channel
        }
        
        if args.test_slack:
            if test_slack_notification(args.slack_token, args.slack_channel):
                logger.info("Slack notification test passed")
            else:
                logger.error("Slack notification test failed")
                sys.exit(1)
    
    # Create configurations for each log file
    log_configs = {}
    for path in args.log_paths:
        log_configs[path] = LogFileConfig(
            path=path,
            critical_levels=args.critical_levels,
            normal_status_codes=args.normal_status_codes
        )
    
    if args.monitor:
        monitor_log_files(log_configs, args.api_key, args.model, args.provider, args.interval, slack_config)
    else:
        run_demo(log_configs, args.api_key, args.model, args.provider, slack_config) 