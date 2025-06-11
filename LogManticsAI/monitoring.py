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
Handles continuous log monitoring, preprocessing, and LLM interaction for anomaly detection.
Corresponds to Part III and IV of the project scope.
Uses Agno for LLM interaction.
"""

import time
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent
from . import llm_utils
from . import config as LogManticsAI_config
from .agno_utils import create_log_analysis_agent

logger = logging.getLogger(__name__)

class AnomalyStats:
    """Class to track anomaly statistics for thresholds"""
    def __init__(self, thresholds: Dict[str, Any]):
        self.thresholds = thresholds
        self.reset_stats()
    
    def reset_stats(self):
        """Reset all statistics"""
        self.error_count = 0
        self.total_response_times = []
        self.last_reset = datetime.now()
    
    def check_thresholds(self) -> Optional[Dict[str, Any]]:
        """Check if any thresholds are exceeded"""
        now = datetime.now()
        minutes_elapsed = (now - self.last_reset).total_seconds() / 60
        
        violations = {}
        
        # Check error rate
        if minutes_elapsed > 0:
            error_rate = self.error_count / minutes_elapsed
            if error_rate > self.thresholds.get('error_rate', float('inf')):
                violations['error_rate'] = {
                    'current': error_rate,
                    'threshold': self.thresholds['error_rate']
                }
        
        # Check response times
        if self.total_response_times:
            avg_response_time = sum(self.total_response_times) / len(self.total_response_times)
            if avg_response_time > self.thresholds.get('response_time_ms', float('inf')):
                violations['response_time'] = {
                    'current': avg_response_time,
                    'threshold': self.thresholds['response_time_ms']
                }
        
        return violations if violations else None
    
    def update_stats(self, log_entry: Dict[str, Any], field_mappings: Dict[str, str]):
        """Update statistics based on a log entry"""
        # Map fields using custom mappings
        level_field = field_mappings.get('level', 'level')
        if log_entry.get(level_field, '').upper() in ['ERROR', 'CRITICAL']:
            self.error_count += 1
        
        # Check for response time
        duration_field = field_mappings.get('duration', 'duration')
        if duration_field in log_entry:
            try:
                duration = float(log_entry[duration_field])
                self.total_response_times.append(duration)
            except (ValueError, TypeError):
                pass

class LogMonitor:
    """Class to manage monitoring of multiple log files"""
    def __init__(self, config_data):
        self.config_data = config_data
        self.log_handlers = {}
        self.observers = {}  # Now keyed by directory
        self.stats = {
            'total_lines_read': 0,
            'lines_processed': 0,
            'lines_filtered': 0,
            'batches_analyzed': 0,
            'anomalies_detected': 0
        }
        
        # Initialize buffer settings from config
        self.MAX_BUFFER_SIZE = config_data.get('anomaly_detection', {}).get('batch_size', 100)
        self.MAX_BUFFER_TIME_SECONDS = config_data.get('anomaly_detection', {}).get('analysis_interval_sec', 300)
        
        self.processed_log_buffer = []
        self.last_buffer_send_time = time.time()
        
        # Initialize anomaly tracking
        self.anomaly_stats = AnomalyStats(config_data.get('anomaly_detection', {}))

    def start_monitoring(self):
        """Start monitoring all configured log files"""
        if 'log_files' not in self.config_data:
            logger.error("No log files configured for monitoring")
            return

        # Convert relative paths to absolute paths
        resolved_log_files = {}
        current_dir = os.getcwd()
        
        for log_file_path, file_config in self.config_data['log_files'].items():
            # Check if this is a relative path
            if not os.path.isabs(log_file_path):
                # Convert to absolute path
                abs_path = os.path.abspath(os.path.join(current_dir, log_file_path))
                logger.debug(f"Converting relative path {log_file_path} to absolute path {abs_path}")
                resolved_log_files[abs_path] = file_config
            else:
                resolved_log_files[log_file_path] = file_config

        # Group files by directory
        files_by_dir = {}
        for log_file_path, file_config in resolved_log_files.items():
            dir_path = os.path.dirname(log_file_path)
            if dir_path not in files_by_dir:
                files_by_dir[dir_path] = []
            files_by_dir[dir_path].append((log_file_path, file_config))

        # Create one observer per directory
        for dir_path, file_configs in files_by_dir.items():
            try:
                # Create one observer for this directory
                observer = Observer()
                
                # Create handlers for all files in this directory
                for log_file_path, file_config in file_configs:
                    handler = LogFileHandler(
                        log_file_path=log_file_path,
                        important_keys=file_config['important_keys'],
                        llm_config=self.config_data,
                        file_config=file_config,
                        monitor=self
                    )
                    
                    # Schedule this handler with the directory's observer
                    observer.schedule(handler, path=dir_path, recursive=False)
                    
                    # Store handler
                    self.log_handlers[log_file_path] = handler
                    
                    logger.info(f"Started monitoring {log_file_path}")
                    
                    # Process existing content
                    self.process_existing_content(log_file_path, file_config)
                
                # Start the observer and store it
                observer.start()
                self.observers[dir_path] = observer
                
            except Exception as e:
                logger.error(f"Failed to start monitoring files in {dir_path}: {e}")

        try:
            # Keep main thread alive and handle buffer checks
            start_time = time.time()
            while True:
                time.sleep(10)  # Check buffer every 10 seconds
                self.check_and_flush_buffer(force_flush=False)
                
                # Print statistics periodically
                elapsed_time = time.time() - start_time
                if elapsed_time >= 60:  # Print stats every minute
                    self.log_statistics()
                    start_time = time.time()
                    
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
            self.stop_monitoring()
        except Exception as e:
            logger.error(f"An error occurred during monitoring: {e}")
            self.stop_monitoring()

    def stop_monitoring(self):
        """Stop all file monitoring"""
        # Final flush of buffer
        self.check_and_flush_buffer(force_flush=True)
        
        # Stop all observers
        for observer in self.observers.values():
            observer.stop()
        for observer in self.observers.values():
            observer.join()
            
        # Print final statistics
        self.log_statistics(final=True)

    def process_existing_content(self, log_file_path, file_config):
        """Process existing content in a log file"""
        try:
            logger.info(f"Initializing monitoring for {log_file_path}")
            
            # Check if file exists
            if not os.path.exists(log_file_path):
                logger.error(f"Log file does not exist: {log_file_path}")
                return
                
            file_size = os.path.getsize(log_file_path)
            logger.debug(f"File size of {log_file_path}: {file_size} bytes")
            
            # Check if we want to process existing content or just start monitoring from the end
            process_existing = self.config_data.get('anomaly_detection', {}).get('process_existing_logs', False)
            
            with open(log_file_path, 'r') as file:
                if process_existing:
                    logger.info(f"Processing existing content in {log_file_path}")
                    # TODO: Implement processing of existing log content
                    # This would be similar to on_modified but with a separate buffer
                    pass
                else:
                    # Go to the end of the file and record position
                    file.seek(0, 2)
                    position = file.tell()
                    self.log_handlers[log_file_path].last_position = position
                    logger.info(f"Starting monitoring {log_file_path} from position {position}")
                    
        except Exception as e:
            logger.error(f"Error initializing monitoring for {log_file_path}: {e}", exc_info=True)

    def add_to_buffer(self, processed_entry, source_file):
        """Add a processed entry to the buffer"""
        processed_entry['_logai_source_file'] = source_file
        self.processed_log_buffer.append(processed_entry)
        
        # If entry is critical, check if we should flush immediately
        if processed_entry.get('_logai_is_critical', False):
            logger.info(f"Critical entry added to buffer from {source_file}: {processed_entry.get('message', '')[:100]}")
        
        # Normal buffer check
        self.check_and_flush_buffer(force_flush=False)

    def check_and_flush_buffer(self, force_flush=False):
        """Check buffer conditions and flush if needed"""
        current_time = time.time()
        buffer_full = len(self.processed_log_buffer) >= self.MAX_BUFFER_SIZE
        time_elapsed = (current_time - self.last_buffer_send_time) >= self.MAX_BUFFER_TIME_SECONDS

        if self.processed_log_buffer and (buffer_full or time_elapsed or force_flush):
            logger.info(f"Flushing buffer. Size={len(self.processed_log_buffer)}, Full={buffer_full}, Time={time_elapsed}, Force={force_flush}")
            
            # Create a copy of the buffer for analysis
            buffer_to_analyze = list(self.processed_log_buffer)
            self.processed_log_buffer = []
            self.last_buffer_send_time = current_time
            
            # Update statistics
            self.stats['batches_analyzed'] += 1
            
            # Analyze the buffer asynchronously
            import threading
            analysis_thread = threading.Thread(
                target=self.analyze_log_batch,
                args=(buffer_to_analyze,)
            )
            analysis_thread.daemon = True
            analysis_thread.start()

    def analyze_log_batch(self, log_batch):
        """Analyze a batch of logs using the LLM"""
        try:
            # Group entries by source file
            entries_by_file = {}
            for entry in log_batch:
                source_file = entry.pop('_logai_source_file', 'unknown')
                if source_file not in entries_by_file:
                    entries_by_file[source_file] = []
                entries_by_file[source_file].append(entry)
            
            # Check anomaly thresholds
            threshold_violations = self.anomaly_stats.check_thresholds()
            if threshold_violations:
                logger.warning("Threshold violations detected:")
                for metric, details in threshold_violations.items():
                    logger.warning(f"- {metric}: Current={details['current']:.2f}, Threshold={details['threshold']}")
                
                # Send threshold violation notification
                self.send_threshold_notification(threshold_violations)
            
            # Analyze each group separately
            for source_file, entries in entries_by_file.items():
                logger.info(f"Analyzing {len(entries)} entries from {source_file}")
                
                # Get file-specific configuration
                file_config = self.config_data['log_files'].get(source_file, {})
                field_mappings = file_config.get('field_mappings', {})
                
                # Update anomaly statistics
                for entry in entries:
                    self.anomaly_stats.update_stats(entry, field_mappings)
                
                # Get the appropriate prompt template
                prompt_template = self.config_data.get('prompts', {}).get('anomaly_detection', '')
                if not prompt_template:
                    logger.warning("No anomaly detection prompt template found, using default")
                    prompt_template = "Analyze these log entries for anomalies:\n{log_entries}"
                
                # Format entries for analysis
                formatted_entries = json.dumps(entries, indent=2)
                prompt = prompt_template.format(log_entries=formatted_entries)
                
                # Send to LLM for analysis
                analysis = llm_utils.send_logs_for_anomaly_detection(
                    entries,
                    self.config_data,
                    prompt=prompt
                )
                
                if analysis:
                    # Extract the content if this is a RunResponse object
                    if hasattr(analysis, 'content'):
                        analysis_text = analysis.content
                    else:
                        analysis_text = str(analysis)
                    
                    # Save the analysis
                    self.save_analysis_to_file(analysis_text, entries, source_file)
                    
                    # Check if analysis indicates anomalies
                    if any(keyword in analysis_text.lower() for keyword in ['anomaly', 'error', 'warning', 'critical']):
                        self.stats['anomalies_detected'] += 1
                        
                        # Send notification if configured
                        if self.config_data.get('slack_enabled') == 'true':
                            self.send_slack_notification(analysis_text, entries, source_file)
                
            # Reset anomaly stats after analysis
            self.anomaly_stats.reset_stats()
            
        except Exception as e:
            logger.error(f"Error analyzing log batch: {e}")

    def save_analysis_to_file(self, analysis, log_batch, source_file):
        """Save analysis results to file and handle notifications"""
        try:
            # Create directory if it doesn't exist
            results_dir = os.path.expanduser("~/.config/LogManticsAI/results")
            os.makedirs(results_dir, exist_ok=True)
            
            # Create a filename with timestamp and source file
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            source_file_name = os.path.basename(source_file)
            filename = os.path.join(results_dir, f"analysis-{source_file_name}-{timestamp}.txt")
            
            # Extract the content if this is a RunResponse object
            if hasattr(analysis, 'content'):
                analysis_text = analysis.content
            else:
                analysis_text = str(analysis)
            
            # Parse and format the analysis
            from .utils import parse_llm_analysis, format_analysis_result
            parsed_analysis = parse_llm_analysis(analysis_text)
            formatted_analysis = format_analysis_result(parsed_analysis)
            
            with open(filename, 'w') as f:
                f.write(f"=== LogManticsAI Analysis Results for {source_file} ===\n\n")
                f.write(formatted_analysis)
                f.write("\n\n=== Raw Analysis ===\n\n")
                f.write(analysis_text)
                f.write("\n\n=== Analyzed Log Entries ===\n\n")
                for entry in log_batch:
                    f.write(json.dumps(entry, indent=2))
                    f.write("\n\n")
            
            logger.info(f"Analysis saved to {filename}")
            
            # Handle Slack notifications if enabled
            if self.config_data.get('slack_enabled', '').lower() == 'true':
                self.send_slack_notification(parsed_analysis, log_batch, source_file)
                
        except Exception as e:
            logger.error(f"Error saving analysis to file: {e}", exc_info=True)

    def send_slack_notification(self, parsed_analysis, log_batch, source_file):
        """Send analysis results to Slack"""
        try:
            from .slack_utils import send_analysis_to_slack
            slack_config = {
                'slack_token': self.config_data.get('slack_token', ''),
                'slack_channel': self.config_data.get('slack_channel', '')
            }
            
            if not all(slack_config.values()):
                logger.error("Incomplete Slack configuration")
                return
            
            # Ensure parsed_analysis is a dictionary
            if isinstance(parsed_analysis, str):
                # If it's a string, create a simple dictionary with the text as summary
                parsed_analysis = {
                    'summary': parsed_analysis,
                    'anomalies': [],
                    'recommendations': [],
                    'severity': 'medium'
                }
            elif not isinstance(parsed_analysis, dict):
                # If it's neither string nor dict, convert to string and use as summary
                parsed_analysis = {
                    'summary': str(parsed_analysis),
                    'anomalies': [],
                    'recommendations': [],
                    'severity': 'medium'
                }
            
            # Don't fail monitoring if Slack send fails
            try:
                success = send_analysis_to_slack(parsed_analysis, log_batch, slack_config, source_file)
                if success:
                    logger.info(f"Analysis for {source_file} posted to Slack successfully")
                else:
                    logger.warning(f"Failed to post analysis for {source_file} to Slack")
            except Exception as slack_error:
                logger.error(f"Error sending Slack notification: {slack_error}", exc_info=True)
                
        except Exception as e:
            logger.error(f"Error preparing Slack notification: {e}", exc_info=True)

    def send_threshold_notification(self, violations: Dict[str, Any]):
        """Send notification for threshold violations"""
        if self.config_data.get('slack_enabled') != 'true':
            return
        
        message = "🚨 *Anomaly Threshold Violations Detected*\n\n"
        for metric, details in violations.items():
            message += f"*{metric}*\n"
            message += f"- Current Value: {details['current']:.2f}\n"
            message += f"- Threshold: {details['threshold']}\n\n"
        
        try:
            from .slack_utils import send_slack_message
            send_slack_message(
                self.config_data['slack_token'],
                self.config_data['slack_channel'],
                message
            )
        except Exception as e:
            logger.error(f"Failed to send threshold violation notification: {e}")

    def log_statistics(self, final=False):
        """Log monitoring statistics"""
        prefix = "Final" if final else "Current"
        logger.info(f"{prefix} statistics: "
                   f"Read {self.stats['total_lines_read']} lines, "
                   f"Processed {self.stats['lines_processed']} warning/error logs, "
                   f"Filtered {self.stats['lines_filtered']} normal logs, "
                   f"Analyzed {self.stats['batches_analyzed']} batches, "
                   f"Anomalies Detected: {self.stats['anomalies_detected']}")

class LogFileHandler(FileSystemEventHandler):
    """Handler for monitoring a specific log file"""
    def __init__(self, log_file_path, important_keys, llm_config, file_config, monitor):
        self.log_file_path = log_file_path
        self.important_keys = important_keys
        self.llm_config = llm_config
        self.file_config = file_config
        self.monitor = monitor
        self.last_position = 0
        
        # Get field mappings for this file
        self.field_mappings = file_config.get('field_mappings', {})
        
        # Set up critical levels
        self.critical_levels = set(level.upper() for level in file_config.get('critical_levels', []))
        self.normal_status_codes = set(str(code) for code in file_config.get('normal_status_codes', []))

    def on_modified(self, event):
        """Called when the log file is modified"""
        if not isinstance(event, FileModifiedEvent):
            return
            
        if event.src_path != self.log_file_path:
            return
            
        try:
            logger.debug(f"File modified event received for {self.log_file_path}")
            logger.debug(f"Current file position: {self.last_position}")
            
            file_size = os.path.getsize(self.log_file_path)
            logger.debug(f"Current file size: {file_size} bytes")
            
            if self.last_position > file_size:
                logger.warning(f"File {self.log_file_path} appears to have been truncated or recreated. Resetting position.")
                self.last_position = 0
            
            with open(self.log_file_path, 'r') as file:
                # Seek to last processed position
                file.seek(self.last_position)
                new_lines = file.readlines()
                
                # Debug - log what we found
                if new_lines:
                    logger.debug(f"Found {len(new_lines)} new lines in {self.log_file_path}")
                else:
                    logger.debug(f"No new lines found in {self.log_file_path}")
                
                # Update statistics
                self.monitor.stats['total_lines_read'] += len(new_lines)
                
                # Process new lines
                for line in new_lines:
                    try:
                        # Try to parse the JSON to check if it would be filtered
                        log_entry = json.loads(line.strip())
                        
                        # Get field mappings - check if the mapped level field exists
                        level_field = self.field_mappings.get('level', 'level')
                        level = log_entry.get(level_field, "").upper()
                        
                        # Get status code field - use mapping if available
                        status_field = self.field_mappings.get('status_code', 'status_code') 
                        status_code = log_entry.get(status_field, 200)
                        
                        # Get filtering configuration for this file
                        critical_levels = self.file_config.get('critical_levels', ["WARNING", "ERROR", "CRITICAL"])
                        normal_status_codes = self.file_config.get('normal_status_codes', [0, 200])
                        
                        # Debug log the entry
                        logger.debug(f"Processing log entry: {level}:{status_code} - {log_entry.get('message', '')[:50]}")
                        
                        # Check if it meets filtering criteria
                        if level in critical_levels or (status_code not in normal_status_codes):
                            logger.debug(f"Processing critical log: {level}:{status_code}")
                            processed_entry = self.process_log_entry(line)
                            if processed_entry:
                                self.monitor.stats['lines_processed'] += 1
                                self.monitor.add_to_buffer(processed_entry, self.log_file_path)
                            else:
                                logger.warning(f"Failed to process log entry: {line[:100]}...")
                        else:
                            self.monitor.stats['lines_filtered'] += 1
                            logger.debug(f"Filtered normal log: {level}:{status_code}")
                    except json.JSONDecodeError:
                        logger.warning(f"Skipping malformed JSON log line in {self.log_file_path}: {line[:100]}...")
                
                # Update position
                new_position = file.tell()
                logger.debug(f"Updated file position for {self.log_file_path} from {self.last_position} to {new_position}")
                self.last_position = new_position
        except Exception as e:
            logger.error(f"Error processing updates for {self.log_file_path}: {e}", exc_info=True)

    def process_log_entry(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Process a single log line"""
        try:
            # Parse JSON
            entry = json.loads(log_line)
            
            # Apply field mappings
            mapped_entry = {}
            for std_field, custom_field in self.field_mappings.items():
                if custom_field in entry:
                    mapped_entry[std_field] = entry[custom_field]
            
            # Add unmapped fields
            for key, value in entry.items():
                if key not in mapped_entry.values():
                    mapped_entry[key] = value
            
            # Check if this is a critical entry
            is_critical = False
            
            # Check log level
            level_field = self.field_mappings.get('level', 'level')
            if mapped_entry.get(level_field, '').upper() in self.critical_levels:
                is_critical = True
            
            # Check status code
            status_field = self.field_mappings.get('status_code', 'status_code')
            if status_field in mapped_entry:
                status = str(mapped_entry[status_field])
                if status not in self.normal_status_codes:
                    is_critical = True
            
            # Add metadata
            mapped_entry['_logai_is_critical'] = is_critical
            mapped_entry['_logai_timestamp'] = datetime.now().isoformat()
            
            # Log that we're processing the entry
            logger.debug(f"Processed log entry: {mapped_entry.get('message', '')[:50]}")
            
            # Return the processed entry
            return mapped_entry
            
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON in log line: {log_line[:100]}...")
            return None
        except Exception as e:
            logger.error(f"Error processing log entry: {e}", exc_info=True)
            return None

def start_monitoring(log_files, config_data):
    """Start monitoring all configured log files"""
    monitor = LogMonitor(config_data)
    monitor.start_monitoring()

# Register cleanup handler
import atexit
def cleanup_handler():
    """Cleanup handler to flush buffer on exit"""
    config = LogManticsAI_config.load_yaml_config('config')
    if config:
        LogMonitor(config).check_and_flush_buffer(force_flush=True)
    else:
        # No config, just log a message
        logger.debug("No configuration found during cleanup, skipping buffer flush")

atexit.register(cleanup_handler) 