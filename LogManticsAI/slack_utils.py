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
Utilities for Slack integration with LogManticsAI.
Provides functions for sending analysis results to Slack channels,
testing Slack configuration, and formatting messages.
"""

import logging
import json
from typing import Dict, Any, Optional
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

logger = logging.getLogger(__name__)

def validate_slack_config(slack_token: str, slack_channel: str) -> bool:
    """Validates Slack configuration by sending and deleting a test message"""
    logger.info(f"Testing Slack configuration for channel: {slack_channel}")

    # Try different channel name formats
    channel_formats = []
    
    # Add original channel format
    channel_formats.append(slack_channel)
    
    # If channel doesn't start with #, add version with #
    if slack_channel and not slack_channel.startswith('#') and not slack_channel.startswith('C'):
        channel_formats.append(f"#{slack_channel}")
    
    # If channel starts with #, add version without #
    if slack_channel and slack_channel.startswith('#'):
        channel_formats.append(slack_channel[1:])
    
    # Try each channel format
    for channel in channel_formats:
        logger.info(f"Attempting to post to channel format: {channel}")
        try:
            # Initialize Slack client
            client = WebClient(token=slack_token)
            
            # Try to post a test message
            response = client.chat_postMessage(
                channel=channel,
                text="LogManticsAI connection test (this message will be deleted)",
            )
            
            # If successful posting, we consider this a success
            # Don't worry about deletion failures
            if response['ok'] and 'ts' in response:
                logger.info(f"Successfully posted to channel: {channel}")
                
                # Try to delete, but don't fail validation if deletion fails
                try:
                    client.chat_delete(
                        channel=channel,
                        ts=response['ts']
                    )
                    logger.info("Test message deleted successfully")
                except Exception as e:
                    # Just log the error but consider validation successful
                    logger.warning(f"Could not delete test message: {e}")
                
                # Return success even if deletion failed
                return True
                
        except SlackApiError as e:
            error_code = e.response.get("error", "unknown_error")
            logger.error(f"Slack API error with channel '{channel}': code={error_code}, details={e}")
            # Continue with next format
        except Exception as e:
            logger.error(f"Unexpected error with channel '{channel}': {e}")
            # Continue with next format
    
    # If we got here, all formats failed
    logger.error("All channel formats failed. Please check:")
    logger.error("1. The channel exists in your workspace")
    logger.error("2. The bot has been added to the channel")
    logger.error("3. For private channels, use the channel ID instead of name")
    return False

def send_analysis_to_slack(analysis_result: Dict[str, Any], log_batch: list, slack_config: Dict[str, str], log_file_path: str = None) -> bool:
    """
    Sends formatted analysis results to the configured Slack channel.
    Returns True if successful, False otherwise.
    
    Args:
        analysis_result: Parsed analysis results
        log_batch: The log entries that were analyzed
        slack_config: Dictionary with 'slack_token' and 'slack_channel'
        log_file_path: Path to the log file being monitored
    """
    if not slack_config:
        logger.debug("Slack posting skipped - slack_config is None or empty")
        return False
        
    if not slack_config.get('slack_token'):
        logger.debug("Slack posting skipped - missing slack_token")
        return False
        
    if not slack_config.get('slack_channel'):
        logger.debug("Slack posting skipped - missing slack_channel")
        return False
    
    # Validate that analysis_result is a dictionary
    if not isinstance(analysis_result, dict):
        logger.error(f"Invalid analysis_result type: {type(analysis_result)}. Expected dict.")
        # Convert to a simple dictionary to avoid errors
        analysis_result = {
            'summary': str(analysis_result),
            'anomalies': [],
            'recommendations': [],
            'severity': 'unknown'
        }
    
    token = slack_config.get('slack_token')
    channel = slack_config.get('slack_channel')
    
    # Format channel name correctly
    if channel and not channel.startswith('#') and not channel.startswith('C'):
        channel = f"#{channel}"
        logger.debug(f"Formatted channel name to: {channel}")
    
    logger.info(f"Preparing to send analysis to Slack channel: {channel}")
    
    # Safely access dictionary values
    severity = analysis_result.get('severity', 'unknown')
    if isinstance(severity, str):
        severity = severity.upper()
    else:
        severity = 'UNKNOWN'
        
    anomalies = analysis_result.get('anomalies', [])
    if not isinstance(anomalies, list):
        logger.warning(f"Expected anomalies to be a list, got {type(anomalies)}")
        anomalies = []
        
    logger.debug(f"Analysis severity: {severity}")
    logger.debug(f"Analysis contains {len(anomalies)} anomalies")
    
    try:
        client = WebClient(token=token)
        
        # Format the message for Slack
        severity_emoji = {
            'CRITICAL': ':red_circle:',
            'HIGH': ':warning:',
            'MEDIUM': ':large_blue_circle:',
            'LOW': ':white_check_mark:',
            'UNKNOWN': ':question:'
        }.get(severity, ':question:')
        
        # Create message header
        header = f"{severity_emoji} *LOG ANALYSIS RESULTS - {severity} SEVERITY*"
        if log_file_path:
            header += f"\n*Log File:* `{log_file_path}`"
        
        # Create message blocks for Slack's block kit
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"LogManticsAI Analysis Results ({severity})"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": header
                }
            }
        ]
        
        # Add summary section
        if analysis_result.get('summary'):
            prefix = "*SUMMARY:*\n"
            # Ensure raw_summary_content is a string, default to empty string if not found or None
            raw_summary_content = str(analysis_result.get('summary', '')) 
            
            SLACK_TEXT_LIMIT = 3000  # Max characters for a text field in a section
            TRUNCATION_SUFFIX = "... (truncated)"
            
            final_summary_text: str

            # Calculate the maximum length allowed for raw_summary_content if we need to truncate
            # max_len_for_content = limit - len(prefix) - len(suffix)
            available_length_for_raw_content = SLACK_TEXT_LIMIT - len(prefix) - len(TRUNCATION_SUFFIX)
            
            if len(prefix) + len(raw_summary_content) > SLACK_TEXT_LIMIT:
                # Truncation is necessary
                if available_length_for_raw_content > 0:
                    truncated_content = raw_summary_content[:available_length_for_raw_content]
                    final_summary_text = prefix + truncated_content + TRUNCATION_SUFFIX
                else:
                    # This edge case means prefix + suffix alone exceed the limit or leave no space.
                    # Truncate the prefix itself to make space for the suffix.
                    max_prefix_len = SLACK_TEXT_LIMIT - len(TRUNCATION_SUFFIX)
                    if max_prefix_len < 0: 
                        # This implies TRUNCATION_SUFFIX itself is > SLACK_TEXT_LIMIT
                        # Highly unlikely, but if so, just send a truncated suffix.
                        final_summary_text = TRUNCATION_SUFFIX[:SLACK_TEXT_LIMIT]
                    else:
                        final_summary_text = prefix[:max_prefix_len] + TRUNCATION_SUFFIX
            else:
                # No truncation needed, fits within the limit
                final_summary_text = prefix + raw_summary_content
            
            # As a final safety, ensure the constructed text doesn't exceed the hard limit.
            if len(final_summary_text) > SLACK_TEXT_LIMIT:
                # This safeguard might be hit if available_length_for_raw_content was negative and not handled perfectly above,
                # or if TRUNCATION_SUFFIX is very long.
                # We will truncate from the end of the string, preserving the TRUNCATION_SUFFIX if possible.
                safe_truncate_length = SLACK_TEXT_LIMIT - len(TRUNCATION_SUFFIX)
                if safe_truncate_length > 0 :
                     final_summary_text = final_summary_text[:safe_truncate_length] + TRUNCATION_SUFFIX
                else: # If TRUNCATION_SUFFIX itself is too long for the limit
                     final_summary_text = final_summary_text[:SLACK_TEXT_LIMIT]


            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": final_summary_text
                }
            })
        
        # Add divider
        blocks.append({"type": "divider"})
        
        # Add anomalies section
        if analysis_result.get('anomalies'):
            anomaly_text = "*DETECTED ANOMALIES:*\n"
            
            # Split anomalies into chunks if there are many
            anomaly_chunks = []
            current_chunk = anomaly_text
            
            for i, anomaly in enumerate(analysis_result['anomalies'], 1):
                anomaly_line = f"• {anomaly['description']}\n"
                
                # Check if adding this line would exceed limit
                if len(current_chunk) + len(anomaly_line) > 2900:
                    # Save current chunk and start a new one
                    anomaly_chunks.append(current_chunk)
                    current_chunk = f"*DETECTED ANOMALIES (continued):*\n{anomaly_line}"
                else:
                    current_chunk += anomaly_line
            
            # Add the last chunk
            if current_chunk:
                anomaly_chunks.append(current_chunk)
            
            # Add each chunk as a separate block
            for chunk in anomaly_chunks:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": chunk
                    }
                })
            
        # Add recommendations section
        if analysis_result.get('recommendations'):
            rec_text = "*RECOMMENDATIONS:*\n"
            
            # Split recommendations into chunks if there are many
            rec_chunks = []
            current_chunk = rec_text
            
            for i, rec in enumerate(analysis_result['recommendations'], 1):
                rec_line = f"• {rec}\n"
                
                # Check if adding this line would exceed limit
                if len(current_chunk) + len(rec_line) > 2900:
                    # Save current chunk and start a new one
                    rec_chunks.append(current_chunk)
                    current_chunk = f"*RECOMMENDATIONS (continued):*\n{rec_line}"
                else:
                    current_chunk += rec_line
            
            # Add the last chunk
            if current_chunk:
                rec_chunks.append(current_chunk)
            
            # Add each chunk as a separate block
            for chunk in rec_chunks:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": chunk
                    }
                })
        
        # Add divider before log entries
        blocks.append({"type": "divider"})
        
        # Add section for log entries header
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*ANALYZED LOG ENTRIES:*"
            }
        })
        
        # Add log entries (limit to 3 and include only key details to avoid message size limits)
        max_entries = min(3, len(log_batch))
        for i in range(max_entries):
            # Format each log entry as a code block
            log_entry = log_batch[i]
            # Extract the most important keys for a compact representation
            important_keys = ['timestamp', 'level', 'message', 'status_code', 'error', 'exception']
            # Filter the log entry to include only important keys that exist
            filtered_entry = {k: log_entry[k] for k in important_keys if k in log_entry}
            # Add any other keys that might be present
            for k, v in log_entry.items():
                if k not in filtered_entry and k not in ['_logai_priority', '_logai_is_critical', '_logai_processed_time']:
                    filtered_entry[k] = v
                    # Limit to ~10 keys max to avoid overly large messages
                    if len(filtered_entry) >= 10:
                        break
            
            entry_json = json.dumps(filtered_entry, indent=2)
            # Truncate very long entries
            if len(entry_json) > 500:
                entry_json = entry_json[:500] + "...\n}"
            
            # Make sure the entry text doesn't exceed Slack's limit
            entry_text = f"*Entry {i+1}:*\n```{entry_json}```"
            if len(entry_text) > 2900:
                entry_text = entry_text[:2900] + "```\n(truncated)"
                
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": entry_text
                }
            })
        
        # If there are more entries than we're showing, add a note
        if len(log_batch) > max_entries:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*+ {len(log_batch) - max_entries} more entries*"
                }
            })
        
        logger.debug(f"Sending message with {len(blocks)} blocks to Slack")
        
        # Split blocks into chunks to avoid hitting message size limits
        # Slack has a limit of 50 blocks per message, and text blocks are limited to 3000 chars
        max_blocks_per_message = 40  # Using 40 to be safe
        
        if len(blocks) <= max_blocks_per_message:
            # Send the message if it's within limits
            response = client.chat_postMessage(
                channel=channel,
                text=f"LogManticsAI Analysis Results - {severity} SEVERITY",  # Fallback text
                blocks=blocks,
                mrkdwn=True
            )
            logger.info(f"Analysis posted to Slack channel {channel} successfully - ts: {response.get('ts')}")
        else:
            # Split into multiple messages
            logger.info(f"Analysis blocks count ({len(blocks)}) exceeds Slack limits. Splitting into multiple messages.")
            
            # Calculate number of parts needed
            num_parts = (len(blocks) + max_blocks_per_message - 1) // max_blocks_per_message
            
            for i in range(num_parts):
                start_idx = i * max_blocks_per_message
                end_idx = min((i + 1) * max_blocks_per_message, len(blocks))
                
                # Add part indicator to the first block if this isn't the first message
                current_blocks = blocks[start_idx:end_idx]
                if i > 0 and len(current_blocks) > 0 and current_blocks[0]["type"] == "section":
                    # Clone the first block and modify its text
                    current_blocks[0] = current_blocks[0].copy()
                    current_text = current_blocks[0]["text"]["text"]
                    current_blocks[0]["text"]["text"] = f"(Part {i+1}/{num_parts}) {current_text}"
                
                response = client.chat_postMessage(
                    channel=channel,
                    text=f"LogManticsAI Analysis Results - Part {i+1}/{num_parts} - {severity} SEVERITY",
                    blocks=current_blocks,
                    mrkdwn=True
                )
                logger.info(f"Analysis part {i+1}/{num_parts} posted to Slack channel {channel} successfully - ts: {response.get('ts')}")
            
            logger.info(f"Successfully sent analysis in {num_parts} messages")
        
        return True
        
    except SlackApiError as e:
        error_code = e.response.get("error", "unknown_error")
        logger.error(f"Slack API error posting to channel '{channel}': code={error_code}, details={e}")
        
        # Add more specific error guidance based on common error codes
        if error_code == "channel_not_found":
            logger.error(f"Channel '{channel}' not found. Make sure you're using the correct channel name (with # for public channels).")
        elif error_code == "not_in_channel":
            logger.error(f"The bot is not a member of channel '{channel}'. Please add the bot to the channel.")
        elif error_code == "invalid_blocks":
            logger.error(f"Invalid message blocks format. This may be due to message content being too long or containing invalid characters.")
            logger.debug(f"Block content summary: {blocks[:2]}")
            
            # Try again with a simplified message if the blocks might be too complex
            try:
                logger.info("Attempting to send a simplified message instead")
                simplified_text = f"LogManticsAI Analysis Results - {severity} SEVERITY\n\n"
                simplified_text += f"Log File: {log_file_path}\n\n"
                simplified_text += f"Summary: {analysis_result.get('summary', 'No summary available')}\n\n"
                simplified_text += f"Detected {len(analysis_result.get('anomalies', []))} anomalies and {len(analysis_result.get('recommendations', []))} recommendations."
                
                response = client.chat_postMessage(
                    channel=channel,
                    text=simplified_text,
                    mrkdwn=True
                )
                logger.info("Simplified message sent successfully")
                return True
            except Exception as fallback_error:
                logger.error(f"Failed to send simplified message: {fallback_error}")
            
        elif error_code == "not_authed":
            logger.error("Not authenticated. The token may be invalid or expired.")
        elif error_code == "token_revoked":
            logger.error("Token has been revoked. Please generate a new token.")
        
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending analysis to Slack: {e}", exc_info=True)
        logger.debug(f"Analysis result keys: {list(analysis_result.keys())}")
        logger.debug(f"Slack config: channel={channel}, token_length={len(token) if token else 0}")
        return False

def send_slack_message(token: str, channel: str, message: str) -> bool:
    """
    Sends a simple text message to Slack.
    Returns True if successful, False otherwise.
    """
    # Format channel name correctly if needed
    if channel and not channel.startswith('#') and not channel.startswith('C'):
        # Add the '#' prefix for public channels that don't already have it
        channel = f"#{channel}"
        
    try:
        logger.debug(f"Sending message to Slack channel: {channel}")
        client = WebClient(token=token)
        
        response = client.chat_postMessage(
            channel=channel,
            text=message,
            mrkdwn=True
        )
        
        if response.get("ok"):
            logger.debug(f"Message sent successfully with timestamp: {response.get('ts')}")
            return True
        else:
            logger.error(f"Failed to send message: {response.get('error')}")
            return False
            
    except SlackApiError as e:
        error_code = e.response.get("error", "unknown_error")
        logger.error(f"Slack API error sending message: code={error_code}, details={e}")
        
        # Try alternative channel format if channel not found
        if error_code in ["channel_not_found", "not_in_channel"]:
            try:
                alt_channel = channel[1:] if channel.startswith('#') else f"#{channel}"
                logger.debug(f"Trying alternative channel format: {alt_channel}")
                alt_response = client.chat_postMessage(
                    channel=alt_channel,
                    text=message,
                    mrkdwn=True
                )
                if alt_response.get("ok"):
                    logger.debug(f"Message sent successfully with alternative channel format")
                    return True
            except:
                pass  # Continue to return False if alternative format also fails
                
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending Slack message: {e}")
        return False 