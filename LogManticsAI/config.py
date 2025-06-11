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
Configuration management for LogManticsAI.
Handles reading and writing configuration settings such as API keys, model, and log file path.
Uses YAML configuration files in ~/.config/LogManticsAI/.
"""

import os
import logging
import keyring
from typing import Dict, Any, Optional
from .config.config_loader import (
    get_config_dir,
    get_config_file_path,
    ensure_config_dir,
    load_yaml_config,
    save_yaml_config,
    reset_config
)

# Constants
KEYRING_SERVICE = "LogManticsAI"
KEYRING_API_KEY = "llm_api_key"

logger = logging.getLogger(__name__)

def get_api_key() -> Optional[str]:
    """Get API key from keyring."""
    try:
        return keyring.get_password(KEYRING_SERVICE, KEYRING_API_KEY)
    except Exception as e:
        logger.error(f"Failed to retrieve API key from keyring: {e}")
        return None

def save_api_key(api_key: str) -> bool:
    """Save API key to keyring."""
    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_API_KEY, api_key)
        return True
    except Exception as e:
        logger.error(f"Failed to save API key to keyring: {e}")
        return False

def delete_api_key() -> bool:
    """Delete API key from keyring."""
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_API_KEY)
        return True
    except Exception as e:
        logger.error(f"Failed to delete API key from keyring: {e}")
        return False

# Re-export config_loader functions
__all__ = [
    'get_config_dir',
    'get_config_file_path',
    'ensure_config_dir',
    'load_yaml_config',
    'save_yaml_config',
    'reset_config',
    'get_api_key',
    'save_api_key',
    'delete_api_key'
] 