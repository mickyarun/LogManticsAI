"""
Default configurations for LogAI.
These configurations are used when initializing the tool for the first time.
"""

import os
import logging
from typing import Dict, Any
from .config_loader import save_yaml_config, ensure_config_dir, get_config_dir

logger = logging.getLogger(__name__)

# Default LLM instructions
DEFAULT_LLM_INSTRUCTIONS = {
    'key_identification': {
        'agent_name': "LogAI Key Identifier",
        'instructions': [
            "You are an expert log analysis assistant.",
            "Your task is to identify the most important keys in JSON log entries for monitoring and anomaly detection.",
            "Focus on keys that indicate errors, performance issues, security concerns, and system state.",
            "Consider both standard log fields and application-specific fields."
        ],
        'prompt_template': """
Given these sample JSON log entries, which keys are most important for analyzing application behavior, 
identifying errors, warnings, performance issues, or security anomalies? 
Please list the key names, separated by commas. Only list the key names.

Sample Entries:
{sample_entries}
"""
    },
    'anomaly_detection': {
        'agent_name': "LogAI Anomaly Detector",
        'instructions': [
            "You are an expert log analysis assistant.",
            "Your task is to analyze batches of log entries for anomalies, patterns, and issues.",
            "Focus on identifying critical issues, error patterns, performance degradation, and security concerns.",
            "Provide clear, actionable insights about any anomalies detected."
        ],
        'prompt_template': """
Analyze the following batch of {batch_size} log entries for anomalies, patterns, or issues.
Focus on:
1. Error patterns and their severity
2. Performance degradation indicators
3. Security-related concerns
4. Unusual system state changes
5. Correlations between events

Log Entries:
{batch_json}

Please provide a structured analysis of any anomalies or issues found, including:
- Severity level
- Type of anomaly
- Potential impact
- Recommended actions
"""
    }
}

def initialize_config_files() -> bool:
    """
    Initialize configuration files with default values if they don't exist.
    Returns True if initialization was successful or files already exist.
    """
    try:
        config_dir = ensure_config_dir()
        logger.info(f"Using configuration directory: {config_dir}")
        
        # Initialize LLM instructions
        llm_instructions_file = os.path.join(config_dir, 'llm_instructions.yaml')
        if not os.path.exists(llm_instructions_file):
            logger.info("Creating default LLM instructions configuration...")
            if save_yaml_config('llm_instructions', DEFAULT_LLM_INSTRUCTIONS):
                logger.info("Default LLM instructions configuration created successfully")
            else:
                logger.error("Failed to create default LLM instructions configuration")
                return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error initializing configuration files: {e}")
        return False 