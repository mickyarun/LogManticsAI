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
Utilities for interacting with the configured Large Language Model (LLM).
This includes preparing prompts and sending requests to the LLM API.
Uses Agno for LLM interactions.
"""

import json
import logging
import keyring
from agno.agent import Agent
from typing import List, Dict, Any, Optional
from .agno_utils import create_model, create_log_analysis_agent
from .config.config_loader import load_yaml_config
from .config.defaults import DEFAULT_LLM_INSTRUCTIONS

logger = logging.getLogger(__name__)

def log_response_metrics(response, function_name: str):
    """
    Log response metrics from an LLM call.
    
    Args:
        response: The response object from the LLM
        function_name: Name of the function making the LLM call
    """
    try:
        metrics = {
            'input_tokens': [0],
            'output_tokens': [0],
            'total_tokens': [0],
            'audio_tokens': [0],
            'input_audio_tokens': [0],
            'output_audio_tokens': [0],
            'cached_tokens': [0],
            'reasoning_tokens': [0],
            'prompt_tokens': [0],
            'completion_tokens': [0],
            'prompt_tokens_details': [{'audio_tokens': 0, 'cached_tokens': 0}]
        }
        
        # Extract metrics from response if available
        if hasattr(response, 'usage'):
            usage = response.usage
            if hasattr(usage, 'prompt_tokens'):
                metrics['prompt_tokens'] = [usage.prompt_tokens]
                metrics['input_tokens'] = [usage.prompt_tokens]
            if hasattr(usage, 'completion_tokens'):
                metrics['completion_tokens'] = [usage.completion_tokens]
                metrics['output_tokens'] = [usage.completion_tokens]
            if hasattr(usage, 'total_tokens'):
                metrics['total_tokens'] = [usage.total_tokens]
        
        logger.info(f"LLM Response Metrics for {function_name}:")
        logger.info(f"metrics={json.dumps(metrics, indent=2)}")
        
        return metrics
    except Exception as e:
        logger.warning(f"Error logging response metrics: {e}")
        return None

def get_important_keys_from_llm(sample_log_entries, llm_config):
    """
    Sends sample log entries to the LLM and asks for important keys.
    sample_log_entries: A list of log entry dictionaries.
    llm_config: Dictionary containing 'llm_model' and 'llm_api_key'.
    Returns a list of key names suggested by the LLM.
    """
    model_type = llm_config.get('llm_provider', 'OPENAI')
    model_name = llm_config.get('llm_model', 'gpt-4')
    
    # Get API key - first try to get from keyring if secured, otherwise from config
    api_key = None
    if llm_config.get('api_key_secured') == 'true':
        try:
            api_key = keyring.get_password("LogManticsAI", "llm_api_key")
            if not api_key:
                logger.warning("Could not retrieve API key from keyring, falling back to config")
                api_key = llm_config.get('llm_api_key')
        except Exception as e:
            logger.warning(f"Error retrieving API key from keyring: {e}, falling back to config")
            api_key = llm_config.get('llm_api_key')
    else:
        api_key = llm_config.get('llm_api_key')

    if not model_name or not api_key:
        logger.error("Error: LLM model or API key not configured.")
        return []

    try:
        # Create an Agno model
        model = create_model(model_type, api_key, model_name, max_tokens=500)
        
        # Get key identification configuration
        llm_instructions = load_yaml_config('llm_instructions')
        if not llm_instructions:
            logger.warning("LLM instructions configuration not found, using defaults")
            llm_instructions = DEFAULT_LLM_INSTRUCTIONS
            
        key_id_config = llm_instructions['key_identification']
        
        # Create a simple agent for key identification
        agent = Agent(
            name=key_id_config['agent_name'],
            model=model,
            instructions=key_id_config['instructions'],
            debug_mode=False
        )

        # Prepare the sample entries
        sample_entries_str = "\n".join(json.dumps(entry) for entry in sample_log_entries)
        
        # Format the prompt using the template
        prompt_content = key_id_config['prompt_template'].format(
            sample_entries=sample_entries_str
        )

        logger.info("--- Sending Prompt to LLM for Key Identification ---")
        
        # Get response from Agno agent
        response = agent.run(message=prompt_content)
        
        # Log response metrics
        log_response_metrics(response, "get_important_keys_from_llm")
        
        # Extract key names from the response
        # Handle different response types (String or RunResponse)
        if hasattr(response, 'content'):
            # This is a RunResponse object
            suggested_keys_str = response.content
        else:
            # This is a plain string
            suggested_keys_str = response
            
        logger.info(f"LLM Response for keys: {suggested_keys_str}")
        
        # Parse the response to extract key names
        suggested_keys = [key.strip() for key in suggested_keys_str.split(',') if key.strip()]
        return suggested_keys
        
    except Exception as e:
        logger.error(f"Error communicating with LLM for key identification: {e}")
        return []

def get_common_keys_from_samples(sample_entries):
    """
    Extract common keys from sample log entries.
    Returns a list of keys that appear in at least 50% of samples.
    """
    if not sample_entries:
        return []
        
    # Count key occurrences across all samples
    key_counts = {}
    for entry in sample_entries:
        for key in entry.keys():
            key_counts[key] = key_counts.get(key, 0) + 1
    
    # Find keys that appear in at least half of the samples
    threshold = max(1, len(sample_entries) // 2)
    common_keys = [key for key, count in key_counts.items() if count >= threshold]
    
    return common_keys

def send_logs_for_important_key_identification(sample_entries, llm_config):
    """
    Send sample JSON log entries to LLM to identify important keys for monitoring.
    """
    logger.info("Sending sample logs to LLM for important key identification...")

    try:
        sample_json = json.dumps(sample_entries, indent=2)
        common_keys = get_common_keys_from_samples(sample_entries)
        logger.info(f"Identified {len(common_keys)} common keys in the samples: {', '.join(common_keys)}")
        
        # Parse config values
        model_type = llm_config.get('llm_provider', 'OPENAI')
        model_name = llm_config.get('llm_model', 'gpt-3.5-turbo')
        
        # Get API key - first try from config, then from keyring
        api_key = llm_config.get('api_key')
        if not api_key and llm_config.get('api_key_secured') == 'true':
            api_key = keyring.get_password("LogManticsAI", "llm_api_key")
            
        if not api_key:
            logger.error("No API key found for LLM")
            return []
            
        # Create a simple client
        agent = create_log_analysis_agent(
            model_type=model_type,
            api_key=api_key,
            model_name=model_name
        )
            
        # Prepare the prompt for key identification
        prompt = (
            "I have JSON formatted log entries. Please identify the most important keys for monitoring "
            "application behavior, detecting errors, warnings, performance issues, and security anomalies.\n\n"
            "Here are some sample log entries:\n"
            f"{sample_json}\n\n"
            "What are the most important keys to monitor in these logs? "
            "Please list only the key names, separated by commas, in order of importance."
        )
        
        # Get response from the agent
        response = agent.run(message=prompt)
        
        # Log response metrics
        log_response_metrics(response, "send_logs_for_important_key_identification")
        
        # Extract key names from the response
        if hasattr(response, 'content'):
            suggested_keys_str = response.content
        else:
            suggested_keys_str = response
        
        logger.info(f"LLM Response for keys: {suggested_keys_str}")
        
        # Parse the response to extract key names
        suggested_keys = [key.strip() for key in suggested_keys_str.split(',') if key.strip()]
        return suggested_keys
        
    except Exception as e:
        logger.error(f"Error communicating with LLM for important key identification: {e}")
        return []

def send_logs_for_anomaly_detection(processed_log_batch, llm_config, prompt=None):
    """
    Send the collected and processed log entries to the LLM for anomaly detection.
    Returns the LLM's analysis of the logs.
    """
    logger.info(f"Preparing to send {len(processed_log_batch)} log entries for analysis...")
    
    if not processed_log_batch:
        logger.warning("No log entries to analyze")
        return None
    
    try:
        # Parse configuration
        model_type = llm_config.get('llm_provider', 'OPENAI')
        model_name = llm_config.get('llm_model', 'gpt-3.5-turbo')
        
        # Get API key - first try from config, then from keyring
        api_key = llm_config.get('api_key')
        if not api_key and llm_config.get('api_key_secured') == 'true':
            api_key = keyring.get_password("LogManticsAI", "llm_api_key")
            
        if not api_key:
            logger.error("No API key found for anomaly detection")
            return None
        
        # Get important keys from config
        all_important_keys = set()
        for file_config in llm_config.get('log_files', {}).values():
            if 'important_keys' in file_config:
                all_important_keys.update(file_config['important_keys'])
        
        important_keys = list(all_important_keys)
        
        # Get anomaly detection configuration
        llm_instructions = load_yaml_config('llm_instructions')
        if not llm_instructions:
            logger.warning("LLM instructions configuration not found, using defaults")
            llm_instructions = DEFAULT_LLM_INSTRUCTIONS
            
        anomaly_config = llm_instructions['anomaly_detection']
        
        # Create an Agno log analysis agent
        agent = create_log_analysis_agent(
            model_type=model_type,
            api_key=api_key,
            model_name=model_name,
            important_keys=important_keys,
            instructions=anomaly_config['instructions']
        )

        # Use provided prompt or format the default template
        if not prompt:
            batch_json = json.dumps(processed_log_batch, indent=2)
            prompt = anomaly_config['prompt_template'].format(
                batch_size=len(processed_log_batch),
                batch_json=batch_json
            )
        
        logger.info(f"--- Sending Batch of {len(processed_log_batch)} Logs to LLM for Anomaly Detection ---")
        
        # Get analysis from the agent
        analysis = agent.run(message=prompt)
        
        # Extract content from RunResponse if needed
        if hasattr(analysis, 'content'):
            analysis_text = analysis.content
        else:
            analysis_text = analysis
        
        # Log response metrics
        log_response_metrics(analysis, "send_logs_for_anomaly_detection")
        
        logger.info("--- LLM Anomaly Detection Response Received ---")
        
        return analysis_text
        
    except Exception as e:
        logger.error(f"Error communicating with LLM for anomaly detection: {e}")
        return None 