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

import os
import yaml
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def get_config_dir():
    """Get the configuration directory path"""
    return os.path.expanduser("~/.config/LogManticsAI")

def get_config_file_path(config_name='config'):
    """Get the full path to a configuration file"""
    return os.path.join(get_config_dir(), f"{config_name}.yaml")

def ensure_config_dir():
    """Ensure the configuration directory exists"""
    config_dir = get_config_dir()
    os.makedirs(config_dir, exist_ok=True)
    return config_dir

def load_yaml_config(config_name='config'):
    """Load configuration from a YAML file"""
    try:
        config_file = get_config_file_path(config_name)
        if not os.path.exists(config_file):
            logger.debug(f"Configuration file not found: {config_file}")
            return None
            
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
            return config if config else None
            
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return None

def save_yaml_config(config_name, config_data):
    """Save configuration to a YAML file"""
    try:
        # Ensure config directory exists
        ensure_config_dir()
        
        config_file = get_config_file_path(config_name)
        with open(config_file, 'w') as f:
            yaml.safe_dump(config_data, f, default_flow_style=False)
        return True
        
    except Exception as e:
        logger.error(f"Error saving configuration: {e}")
        return False

def reset_config():
    """Reset (delete) all configuration files"""
    try:
        config_dir = get_config_dir()
        if os.path.exists(config_dir):
            for file in os.listdir(config_dir):
                if file.endswith('.yaml'):
                    os.remove(os.path.join(config_dir, file))
        return True
    except Exception as e:
        logger.error(f"Error resetting configuration: {e}")
        return False

def update_config_value(key, value, config_name='config'):
    """Update a single configuration value"""
    try:
        config = load_yaml_config(config_name) or {}
        config[key] = value
        return save_yaml_config(config_name, config)
    except Exception as e:
        logger.error(f"Error updating configuration value: {e}")
        return False 