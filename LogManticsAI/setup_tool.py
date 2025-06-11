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
Handles the initial setup and log analysis (Part I and II of the project scope).
This includes format validation, JSON structure identification, and LLM interaction for key importance.
"""

import json
import logging
from typing import Set, List, Dict, Any, Tuple, Optional
from . import llm_utils
from .config.config_loader import load_yaml_config, save_yaml_config

logger = logging.getLogger(__name__)
MAX_SAMPLE_LINES = 10

# Default configuration for log filtering
DEFAULT_CRITICAL_LEVELS = ["WARNING", "ERROR", "CRITICAL", "FATAL"]
DEFAULT_STATUS_CODES = [0, 200]  # These are the "normal" status codes

class LogFileConfig:
    """Class to hold configuration for a single log file"""
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.format_keys: List[str] = []
        self.important_keys: List[str] = []
        self.critical_levels: List[str] = []
        self.normal_status_codes: List[int] = []
        self.custom_severity_levels: Dict[str, int] = {}  # Maps custom levels to severity (0-100)
        self.custom_status_codes: Dict[int, str] = {}  # Maps status codes to their meaning

def initial_log_analysis_and_key_id(log_file_path: str, config_data=None) -> Tuple[Optional[List[Dict[str, Any]]], Optional[List[str]]]:
    """
    Performs initial analysis of a log file and identifies important keys using LLM.
    Corresponds to Part II of project scope.
    
    Args:
        log_file_path: Path to the log file to analyze
        config_data: Optional configuration data. If None, will be loaded from config file.
        
    Returns:
        Tuple of (sample_lines, important_keys) or (None, None) if analysis fails
    """
    logger.info(f"Starting initial analysis of log file: {log_file_path}")
    
    # Load existing config if not provided
    if config_data is None:
        config_data = load_yaml_config('config')
        if not config_data:
            logger.error("Error: Configuration not found. Cannot proceed with key importance identification.")
            return None, None
    
    # Check for model configuration
    if not config_data.get('llm_model'):
        logger.error("Error: LLM model not configured. Cannot proceed with key importance identification.")
        return None, None
        
    # Check for API key - either in keyring or config
    api_key_secured = config_data.get('api_key_secured') == 'true'
    if api_key_secured:
        try:
            import keyring
            api_key = keyring.get_password("LogManticsAI", "llm_api_key")
            if not api_key:
                logger.error("Error: LLM API key not found in keyring. Cannot proceed with key importance identification.")
                return None, None
        except Exception as e:
            logger.error(f"Error retrieving API key from keyring: {e}")
            return None, None
    else:
        # Check for API key in config
        if not config_data.get('llm_api_key'):
            logger.error("Error: LLM API key not configured. Cannot proceed with key importance identification.")
            return None, None

    # 1. Format Validation & JSON Structure Identification
    sample_lines, common_keys = analyze_log_structure(log_file_path)
    if not sample_lines or not common_keys:
        logger.error(f"Failed to analyze log structure for {log_file_path}")
        return None, None

    logger.info(f"Identified common log keys: {list(common_keys)}")

    # 2. LLM Interaction for Key Importance
    try:
        llm_suggested_keys = llm_utils.get_important_keys_from_llm(sample_lines, config_data)
        if not llm_suggested_keys:
            logger.warning("Could not get key suggestions from LLM, using common keys")
            llm_suggested_keys = list(common_keys)  # Default to all common keys
        else:
            logger.info(f"LLM suggested important keys: {llm_suggested_keys}")
    except Exception as e:
        logger.error(f"Error getting key suggestions from LLM: {e}")
        logger.warning("Using common keys instead of LLM suggestions")
        llm_suggested_keys = list(common_keys)

    # 3. Configure Log Filtering Settings
    critical_levels, normal_codes, custom_levels, custom_codes = analyze_filtering_options(sample_lines)
    
    # 4. Save Analysis Settings
    file_config = {
        'format_keys': list(common_keys),
        'important_keys': llm_suggested_keys,
        'critical_levels': critical_levels,
        'normal_status_codes': normal_codes,
        'custom_severity_levels': custom_levels,
        'custom_status_codes': custom_codes
    }
    
    # Update config with new file settings
    if 'log_files' not in config_data:
        config_data['log_files'] = {}
    config_data['log_files'][log_file_path] = file_config
    
    if save_yaml_config('config', config_data):
        logger.info(f"Log analysis settings saved for {log_file_path}")
    else:
        logger.warning(f"Failed to save analysis settings for {log_file_path}")
    
    return sample_lines, llm_suggested_keys

def analyze_log_structure(log_file_path: str) -> Tuple[Optional[List[Dict[str, Any]]], Optional[Set[str]]]:
    """
    Reads the first few lines of the log file, validates JSON, and identifies common keys.
    Returns a tuple (sample_log_entries_as_dicts, common_key_set).
    Returns (None, None) if file is not valid JSON or other error.
    """
    sample_entries_dicts = []
    common_keys = None

    try:
        with open(log_file_path, 'r') as f:
            for i, line in enumerate(f):
                if i >= MAX_SAMPLE_LINES:
                    break
                try:
                    log_entry = json.loads(line.strip())
                    if not isinstance(log_entry, dict):
                        logger.error(f"Error: Log line {i+1} is valid JSON but not a JSON object (dictionary).")
                        return None, None
                    sample_entries_dicts.append(log_entry)
                    if common_keys is None:
                        common_keys = set(log_entry.keys())
                    else:
                        common_keys.intersection_update(log_entry.keys())
                except json.JSONDecodeError:
                    logger.error(f"Error: Log file does not appear to contain line-delimited JSON. Line {i+1} is not valid JSON.")
                    return None, None
            
        if not sample_entries_dicts:
            logger.error(f"Error: No valid JSON log entries found in the first {MAX_SAMPLE_LINES} lines or file is empty.")
            return None, None
            
        if common_keys is None: # Should not happen if sample_entries_dicts is populated
            logger.error("Error: Could not determine common keys, possibly an empty file or no valid entries.")
            return None, None

    except FileNotFoundError:
        logger.error(f"Error: Log file not found at {log_file_path}")
        return None, None
    except Exception as e:
        logger.error(f"An unexpected error occurred while reading the log file: {e}")
        return None, None
    
    return sample_entries_dicts, common_keys

def analyze_filtering_options(sample_lines: List[Dict[str, Any]]) -> Tuple[List[str], List[int], Dict[str, int], Dict[int, str]]:
    """
    Analyzes sample log entries to determine appropriate filtering settings.
    Returns a tuple of (critical_levels, normal_status_codes, custom_severity_levels, custom_status_codes).
    """
    # Collect all unique levels and status codes from sample data
    unique_levels = set()
    unique_status_codes = set()
    custom_severity_levels = {}
    custom_status_codes = {}
    
    for entry in sample_lines:
        # Handle log levels
        if 'level' in entry:
            level = str(entry['level']).upper()
            unique_levels.add(level)
            
            # Detect custom severity levels
            if level not in DEFAULT_CRITICAL_LEVELS:
                # Assign severity based on level name
                severity = 0
                if any(indicator in level for indicator in ['FAIL', 'SEVERE', 'ALERT']):
                    severity = 90
                elif any(indicator in level for indicator in ['WARN', 'NOTICE']):
                    severity = 50
                elif any(indicator in level for indicator in ['INFO', 'DEBUG', 'TRACE']):
                    severity = 20
                custom_severity_levels[level] = severity
        
        # Handle status codes
        if 'status_code' in entry:
            try:
                status_code = int(entry['status_code'])
                unique_status_codes.add(status_code)
                
                # Detect custom status codes
                if status_code not in DEFAULT_STATUS_CODES:
                    # Assign meaning based on code range
                    if 200 <= status_code < 300:
                        custom_status_codes[status_code] = 'Success'
                    elif 400 <= status_code < 500:
                        custom_status_codes[status_code] = 'Client Error'
                    elif 500 <= status_code < 600:
                        custom_status_codes[status_code] = 'Server Error'
            except (ValueError, TypeError):
                pass

    # Start with defaults
    critical_levels = DEFAULT_CRITICAL_LEVELS.copy()
    normal_status_codes = DEFAULT_STATUS_CODES.copy()

    # Add any additional levels found in the logs that look like they indicate issues
    for level in unique_levels:
        level_upper = level.upper()
        if any(indicator in level_upper for indicator in ['FAIL', 'SEVERE', 'ALERT']):
            if level not in critical_levels:
                critical_levels.append(level)

    # Add any "success" status codes found in the logs (2xx range)
    for code in unique_status_codes:
        if 200 <= code < 300 and code not in normal_status_codes:
            normal_status_codes.append(code)

    logger.info(f"Configured critical log levels: {critical_levels}")
    logger.info(f"Configured normal status codes: {normal_status_codes}")
    logger.info(f"Detected custom severity levels: {custom_severity_levels}")
    logger.info(f"Detected custom status codes: {custom_status_codes}")

    return critical_levels, normal_status_codes, custom_severity_levels, custom_status_codes

# This file will be called by main.py after basic config (API key, model, path) is set up. 