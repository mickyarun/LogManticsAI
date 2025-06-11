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

# LogManticsAI package initializer

import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Import key modules
from .config.config_loader import (
    load_yaml_config,
    save_yaml_config,
    ensure_config_dir,
    get_config_dir,
    reset_config
)

from .config.defaults import initialize_config_files
from .cli_setup import setup
from .monitoring import start_monitoring
from .setup_tool import initial_log_analysis_and_key_id

# Initialize default configurations
if not initialize_config_files():
    logger.warning("Failed to initialize default configurations. Some features may not work correctly.")

__version__ = '0.1.0'
__all__ = [
    'setup',
    'start_monitoring',
    'initial_log_analysis_and_key_id',
    'load_yaml_config',
    'save_yaml_config',
    'ensure_config_dir',
    'get_config_dir',
    'reset_config'
] 