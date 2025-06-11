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
Common utility functions for the LogAI tool.
"""

import re
import json
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)

# Example utility function (can be expanded as needed)
def format_timestamp(ts):
    """Placeholder for formatting timestamps consistently."""
    # import datetime
    # if isinstance(ts, (int, float)):
    #     return datetime.datetime.fromtimestamp(ts).isoformat()
    # return str(ts) # Fallback
    pass

def get_user_confirmation(prompt_message):
    """
    Prompts the user for a yes/no confirmation.
    Returns True for yes, False for no.
    """
    # while True:
    #     response = input(f"{prompt_message} (yes/no): ").strip().lower()
    #     if response in ['yes', 'y']:
    #         return True
    #     elif response in ['no', 'n']:
    #         return False
    #     else:
    #         print("Invalid input. Please enter 'yes' or 'no'.")
    pass

def parse_llm_analysis(analysis_text: str) -> Dict[str, Any]:
    """
    Parse the LLM analysis response into a structured format.
    
    Args:
        analysis_text: The raw text response from the LLM
        
    Returns:
        A dictionary with structured analysis data:
        {
            'summary': str,
            'anomalies': List[Dict],
            'patterns': List[Dict],
            'recommendations': List[str],
            'severity': str
        }
    """
    result = {
        'summary': '',
        'anomalies': [],
        'patterns': [],
        'recommendations': [],
        'severity': 'unknown'
    }
    
    # Try to determine if the response is already in a structured format (JSON)
    try:
        json_data = json.loads(analysis_text)
        if isinstance(json_data, dict):
            logger.info("Detected JSON response from LLM")
            # If it's valid JSON, use it directly with our expected structure
            result.update({k: v for k, v in json_data.items() if k in result})
            return result
    except json.JSONDecodeError:
        # Not JSON, process as text
        pass
    
    # Extract summary (usually the first paragraph)
    paragraphs = [p.strip() for p in analysis_text.split('\n\n') if p.strip()]
    if paragraphs:
        result['summary'] = paragraphs[0]
    
    # Extract severity level
    severity_patterns = [
        r'severity:?\s*(critical|high|medium|low|info)',
        r'(critical|high|medium|low)\s*severity',
        r'severity\s*level:?\s*(critical|high|medium|low|info)'
    ]
    
    for pattern in severity_patterns:
        severity_match = re.search(pattern, analysis_text, re.IGNORECASE)
        if severity_match:
            result['severity'] = severity_match.group(1).lower()
            break
    
    # Extract anomalies
    # Look for sections about anomalies, issues, errors, warnings
    anomaly_section = extract_section(analysis_text, 
                                      ['anomalies', 'issues', 'errors', 'warnings', 'problems'])
    
    if anomaly_section:
        # Extract bullet points or numbered lists
        bullet_points = extract_bullet_points(anomaly_section)
        if bullet_points:
            result['anomalies'] = [{'description': point} for point in bullet_points]
    
    # Extract patterns
    pattern_section = extract_section(analysis_text, 
                                    ['patterns', 'trends', 'correlations'])
    
    if pattern_section:
        bullet_points = extract_bullet_points(pattern_section)
        if bullet_points:
            result['patterns'] = [{'description': point} for point in bullet_points]
    
    # Extract recommendations
    recommendation_section = extract_section(analysis_text, 
                                           ['recommendations', 'suggestions', 'actions', 'next steps'])
    
    if recommendation_section:
        bullet_points = extract_bullet_points(recommendation_section)
        if bullet_points:
            result['recommendations'] = bullet_points
    
    # If no structured data was found in dedicated sections, try to extract from the whole text
    if not result['anomalies'] and not result['patterns'] and not result['recommendations']:
        all_bullets = extract_bullet_points(analysis_text)
        if all_bullets:
            # Make an educated guess about what each bullet might be
            for bullet in all_bullets:
                if any(kw in bullet.lower() for kw in ['recommend', 'suggest', 'should', 'could', 'action']):
                    result['recommendations'].append(bullet)
                elif any(kw in bullet.lower() for kw in ['pattern', 'trend', 'correlation', 'common']):
                    result['patterns'].append({'description': bullet})
                else:
                    result['anomalies'].append({'description': bullet})
    
    return result

def extract_section(text: str, section_names: List[str]) -> Optional[str]:
    """
    Extract a section from text based on potential section headers.
    
    Args:
        text: The text to search in
        section_names: List of possible section names
        
    Returns:
        The extracted section text or None if not found
    """
    for name in section_names:
        # Look for headers like "Anomalies:", "## Anomalies", "2. Anomalies", etc.
        patterns = [
            rf'#{1,3}\s*{name}[:\s]',  # Markdown headers
            rf'{name}:',               # Simple colon headers
            rf'\d+[\.\)]\s*{name}[:\s]', # Numbered headers
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                # Find the start position after the header
                start_pos = match.end()
                
                # Find the end of this section (start of next section or end of text)
                end_pos = len(text)
                
                # Look for the next section header of the same type
                for next_pattern in patterns:
                    next_match = re.search(next_pattern, text[start_pos:], re.IGNORECASE)
                    if next_match:
                        candidate_end = start_pos + next_match.start()
                        end_pos = min(end_pos, candidate_end)
                
                return text[start_pos:end_pos].strip()
    
    return None

def extract_bullet_points(text: str) -> List[str]:
    """
    Extract bullet points or numbered list items from text.
    
    Args:
        text: The text to extract bullet points from
        
    Returns:
        List of bullet point strings
    """
    bullet_patterns = [
        r'^\s*[•\-\*]\s*(.*?)$',            # Bullet points
        r'^\s*\d+[\.\)]\s*(.*?)$',          # Numbered lists
        r'^\s*[a-zA-Z][\.\)]\s*(.*?)$'      # Letter lists
    ]
    
    bullet_points = []
    
    for pattern in bullet_patterns:
        matches = re.finditer(pattern, text, re.MULTILINE)
        for match in matches:
            bullet = match.group(1).strip()
            if bullet and len(bullet) > 3:  # Avoid very short matches
                bullet_points.append(bullet)
    
    return bullet_points

def format_analysis_result(analysis_result: Dict[str, Any]) -> str:
    """
    Format the parsed analysis result into a readable string.
    
    Args:
        analysis_result: The parsed analysis dictionary
        
    Returns:
        A formatted string for display
    """
    output = []
    
    # Add a header with severity level
    severity = analysis_result['severity'].upper()
    severity_color = {
        'critical': '\033[91m',  # Red
        'high': '\033[93m',      # Yellow
        'medium': '\033[94m',    # Blue
        'low': '\033[92m',       # Green
        'unknown': '\033[0m'     # Default
    }.get(analysis_result['severity'].lower(), '\033[0m')
    reset_color = '\033[0m'
    
    output.append(f"\n{'='*50}")
    output.append(f"LOG ANALYSIS RESULTS - {severity_color}{severity} SEVERITY{reset_color}")
    output.append(f"{'='*50}\n")
    
    # Add summary
    if analysis_result['summary']:
        output.append(f"SUMMARY:")
        output.append(f"{analysis_result['summary']}\n")
    
    # Add anomalies
    if analysis_result['anomalies']:
        output.append(f"DETECTED ANOMALIES:")
        for i, anomaly in enumerate(analysis_result['anomalies'], 1):
            output.append(f"  {i}. {anomaly['description']}")
        output.append("")
    
    # Add patterns
    if analysis_result['patterns']:
        output.append(f"IDENTIFIED PATTERNS:")
        for i, pattern in enumerate(analysis_result['patterns'], 1):
            output.append(f"  {i}. {pattern['description']}")
        output.append("")
    
    # Add recommendations
    if analysis_result['recommendations']:
        output.append(f"RECOMMENDATIONS:")
        for i, recommendation in enumerate(analysis_result['recommendations'], 1):
            output.append(f"  {i}. {recommendation}")
        output.append("")
    
    output.append(f"{'='*50}")
    
    return '\n'.join(output) 