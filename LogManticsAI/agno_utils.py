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
Utilities for working with Agno models and agents.
This module adapts functionality from the reference project, simplified for LogAI needs.
"""

from agno.agent import Agent
from agno.models.openai import OpenAIChat
import logging
import os
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

def create_model(model_type: str, api_key: str, model_name: str, max_tokens: int = 1000) -> Any:
    """
    Create and return the specified Agno model based on model_type.
    
    Args:
        model_type: The type of model ('OPENAI', 'ANTHROPIC', etc.)
        api_key: The API key
        model_name: The name/ID of the model (e.g., 'gpt-4', 'claude-3-sonnet')
        max_tokens: Maximum tokens for model output
        
    Returns:
        The initialized Agno model object
        
    Raises:
        ValueError: If the model type is not supported
    """
    model_type = model_type.upper()
    
    try:
        if model_type == 'OPENAI':
            return OpenAIChat(api_key=api_key, id=model_name, max_tokens=max_tokens)
        elif model_type == 'ANTHROPIC':
            from agno.models.anthropic import Claude
            return Claude(api_key=api_key, id=model_name, max_tokens=max_tokens)
        elif model_type == 'GEMINI' or model_type == 'GOOGLE':
            from agno.models.google import Gemini
            return Gemini(api_key=api_key, id=model_name, max_output_tokens=max_tokens)
        elif model_type == 'GROQ':
            from agno.models.groq import Groq
            return Groq(api_key=api_key, id=model_name, max_tokens=max_tokens)

        else:
            raise ValueError(f"Unsupported model type: {model_type}")
    except ImportError as e:
        logger.error(f"Import error when creating model type {model_type}: {str(e)}")
        raise RuntimeError(f"Model type {model_type} is not available in this installation: {str(e)}")
    except Exception as e:
        logger.error(f"Error creating model type {model_type}: {str(e)}")
        raise RuntimeError(f"Failed to initialize model: {str(e)}")

async def test_model_api_key(api_key: str, model_type: str, model_name: str) -> bool:
    """
    Test if the API key is valid for the given model type.
    
    Args:
        api_key: The API key to test
        model_type: The type of model
        model_name: The name of the model
        
    Returns:
        bool: True if the API key is valid, False otherwise
    """
    try:
        # Create a simple model and agent for testing
        model = create_model(model_type, api_key, model_name)
        test_agent = Agent(
            name="LogAI Test Agent",
            model=model,
            instructions="You are a test agent for LogAI. Just respond with 'Test successful.'",
            debug_mode=False
        )
        
        # Run a simple test query
        await test_agent.arun(message="This is a test message to verify API key validity.")
        return True
    except Exception as e:
        logger.error(f"API key test failed for {model_type}/{model_name}: {str(e)}")
        return False

def create_log_analysis_agent(model_type: str, api_key: str, model_name: str, important_keys: List[str], instructions: Optional[List[str]] = None) -> Agent:
    """
    Create an Agno agent specifically for log analysis.
    
    Args:
        model_type: The type of model ('OPENAI', 'ANTHROPIC', etc.)
        api_key: The API key
        model_name: The name/ID of the model
        important_keys: List of keys identified as important for analysis
        instructions: Optional list of additional instructions for the agent
        
    Returns:
        An Agno agent configured for log analysis
    """
    model = create_model(model_type, api_key, model_name, max_tokens=1500)
    
    # Default instructions for log analysis
    default_instructions = [
        "You are an expert log analysis assistant for LogAI.",
        "Analyze log entries for anomalies, errors, and security concerns.",
        f"Focus on these important keys: {', '.join(important_keys)}",
        "Provide clear, concise descriptions of any issues you detect.",
        "When appropriate, suggest possible root causes and solutions."
    ]
    
    # Combine default and custom instructions
    if instructions:
        agent_instructions = default_instructions + instructions
    else:
        agent_instructions = default_instructions
    
    # Create and return the agent
    return Agent(
        name="LogAI Analysis Agent",
        model=model,
        instructions=agent_instructions,
        debug_mode=False
    ) 