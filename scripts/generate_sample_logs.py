#!/usr/bin/env python3
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

Generate sample JSON log files for testing LogAI.
This script creates sample log files with various severity levels and patterns for testing.
"""

import json
import random
import time
import os
import argparse
from datetime import datetime, timedelta

# Define log levels
LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# Define sample message templates
MESSAGE_TEMPLATES = {
    "DEBUG": [
        "Database query executed in {duration}ms",
        "HTTP request received for {endpoint}",
        "Cache {status} for key {key}",
        "Thread {thread_id} initialized",
        "Configuration loaded from {filename}"
    ],
    "INFO": [
        "User {user_id} logged in successfully",
        "Transaction {transaction_id} completed",
        "Service {service_name} started",
        "API request processed in {duration}ms",
        "Backup completed successfully, {size}MB saved"
    ],
    "WARNING": [
        "High memory usage detected: {memory_pct}%",
        "Rate limit approaching for API key {api_key}",
        "Slow database query: {duration}ms",
        "Connection pool nearing capacity: {current}/{max} connections",
        "Deprecated API endpoint called: {endpoint}"
    ],
    "ERROR": [
        "Database connection failed: {error_message}",
        "API request failed with status {status_code}",
        "Failed to process transaction {transaction_id}",
        "Uncaught exception in module {module}: {error_message}",
        "Authentication failed for user {user_id}: {reason}"
    ],
    "CRITICAL": [
        "Service unavailable: {service_name} crashed",
        "Data corruption detected in {database}",
        "Failed to recover from system error: {error_code}",
        "Security breach detected from IP {ip_address}",
        "Unrecoverable disk error on volume {volume}"
    ]
}

# Define sample params to fill in templates
SAMPLE_DATA = {
    "duration": lambda: random.randint(5, 2000),
    "endpoint": lambda: random.choice(["/api/users", "/api/products", "/api/orders", "/api/auth", "/api/admin"]),
    "status": lambda: random.choice(["hit", "miss", "expired"]),
    "key": lambda: f"cache:{random.randint(1000, 9999)}",
    "thread_id": lambda: random.randint(1, 100),
    "filename": lambda: random.choice(["config.json", "settings.yml", "app.conf", "env.properties"]),
    "user_id": lambda: f"user_{random.randint(1000, 9999)}",
    "transaction_id": lambda: f"tx_{random.randint(10000, 99999)}",
    "service_name": lambda: random.choice(["auth-service", "payment-service", "api-gateway", "user-service", "notification-service"]),
    "size": lambda: random.randint(10, 500),
    "memory_pct": lambda: random.randint(80, 99),
    "api_key": lambda: f"apk_{random.randint(10000, 99999)}",
    "current": lambda: random.randint(80, 95),
    "max": lambda: 100,
    "error_message": lambda: random.choice(["Connection timeout", "Invalid credentials", "Resource not found", "Permission denied", "Internal server error"]),
    "status_code": lambda: random.choice([400, 401, 403, 404, 500, 502, 503]),
    "module": lambda: random.choice(["auth", "payment", "api", "user", "notification"]),
    "reason": lambda: random.choice(["Invalid password", "Account locked", "IP blocked", "Token expired"]),
    "database": lambda: random.choice(["users", "transactions", "products", "orders", "logs"]),
    "error_code": lambda: f"E{random.randint(1000, 9999)}",
    "ip_address": lambda: f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
    "volume": lambda: f"/dev/sd{random.choice('abcdef')}{random.randint(1, 9)}"
}

# Add new log level and status code configurations
LOG_PROFILES = {
    "app": {
        "levels": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        "weights": [10, 70, 15, 4, 1],  # DEBUG, INFO, WARNING, ERROR, CRITICAL
        "status_codes": [200, 201, 400, 401, 403, 404, 500, 502, 503]
    },
    "api": {
        "levels": ["INFO", "WARN", "ERROR", "SEVERE", "FATAL"],
        "weights": [60, 25, 10, 4, 1],  # INFO, WARN, ERROR, SEVERE, FATAL
        "status_codes": [200, 201, 204, 400, 401, 429, 500, 503]
    },
    "security": {
        "levels": ["NOTICE", "ALERT", "CRITICAL", "EMERGENCY"],
        "weights": [70, 20, 8, 2],  # NOTICE, ALERT, CRITICAL, EMERGENCY
        "status_codes": [200, 401, 403, 407, 429]
    }
}

def generate_log_entry(timestamp=None, level=None, profile="app", include_patterns=True):
    """Generate a single random log entry"""
    if timestamp is None:
        timestamp = datetime.utcnow()
    
    profile_config = LOG_PROFILES[profile]
    
    if level is None:
        # Use profile-specific levels and weights
        level = random.choices(profile_config["levels"], weights=profile_config["weights"], k=1)[0]
    
    # Get a random message template for this level
    # Map custom levels to standard ones for message templates
    template_level = level
    if level in ["WARN", "SEVERE", "FATAL", "NOTICE", "ALERT", "EMERGENCY"]:
        if level in ["WARN", "NOTICE"]: template_level = "WARNING"
        elif level in ["SEVERE", "ALERT"]: template_level = "ERROR"
        elif level in ["FATAL", "EMERGENCY"]: template_level = "CRITICAL"
    
    template = random.choice(MESSAGE_TEMPLATES[template_level])
    
    # Fill in the template parameters
    params = {}
    for param_name in [p.split('}')[0] for p in template.split('{')[1:]]:
        if param_name in SAMPLE_DATA:
            params[param_name] = SAMPLE_DATA[param_name]()
    
    message = template.format(**params)
    
    # Create the log entry with profile-specific status code
    log_entry = {
        "timestamp": timestamp.isoformat(),
        "level": level,
        "message": message,
        "service": profile,
        "environment": random.choice(["prod", "staging", "dev"]),
        "request_id": f"req_{random.randint(10000, 99999)}",
        "duration_ms": random.randint(1, 1000),
        "host": f"server-{random.randint(1, 20)}",
        "status_code": random.choice(profile_config["status_codes"])
    }
    
    # Add some additional fields for certain types of logs
    if level in ["ERROR", "CRITICAL", "SEVERE", "FATAL", "ALERT", "EMERGENCY"]:
        log_entry["error_code"] = f"E{random.randint(1000, 9999)}"
        log_entry["stack_trace"] = "Exception in thread main java.lang.NullPointerException\n\tat com.example.myproject.Book.getTitle(Book.java:16)\n\tat com.example.myproject.Author.getBookTitles(Author.java:25)"
    
    if include_patterns and random.random() < 0.1:
        # Occasionally include some patterns that should be detected as anomalies
        pattern_type = random.randint(1, 3)
        if pattern_type == 1:
            # Sudden elevation of severity
            log_entry["level"] = profile_config["levels"][-1]  # Use highest severity for profile
            log_entry["message"] = "SECURITY ALERT: Potential unauthorized access detected"
            log_entry["security_event"] = True
        elif pattern_type == 2:
            # Performance degradation
            log_entry["duration_ms"] = random.randint(5000, 15000)
            log_entry["message"] = "Extreme latency detected in service response"
        elif pattern_type == 3:
            # Unusual access pattern
            log_entry["message"] = "Unusual access pattern detected"
            log_entry["source_ip"] = "192.168.1.1"
            log_entry["access_attempts"] = random.randint(50, 100)
    
    return log_entry

def generate_log_files(base_dir="logs", num_entries=1000, include_patterns=True):
    """Generate multiple log files with different profiles"""
    os.makedirs(base_dir, exist_ok=True)
    start_time = datetime.utcnow() - timedelta(hours=1)
    time_increment = timedelta(seconds=3.6)  # ~1000 entries per hour
    
    generated_files = {}
    for profile in LOG_PROFILES.keys():
        filename = os.path.join(base_dir, f"{profile}_logs.json")
        with open(filename, 'w') as f:
            current_time = start_time
            for i in range(num_entries):
                log_entry = generate_log_entry(
                    timestamp=current_time,
                    profile=profile,
                    include_patterns=include_patterns
                )
                f.write(json.dumps(log_entry) + '\n')
                current_time += time_increment
        generated_files[profile] = filename
        print(f"Generated {num_entries} {profile} log entries in {filename}")
    
    return generated_files

def generate_continuous_logs_multi(base_dir="logs", interval=1.0, include_patterns=True):
    """Generate logs continuously for multiple profiles"""
    os.makedirs(base_dir, exist_ok=True)
    files = {
        profile: os.path.join(base_dir, f"{profile}_logs.json")
        for profile in LOG_PROFILES.keys()
    }
    
    # Create files if they don't exist
    for filepath in files.values():
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                pass
    
    try:
        print(f"Generating logs continuously to {base_dir} (Ctrl+C to stop)")
        while True:
            for profile, filepath in files.items():
                with open(filepath, 'a') as f:
                    log_entry = generate_log_entry(profile=profile, include_patterns=include_patterns)
                    f.write(json.dumps(log_entry) + '\n')
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nLog generation stopped")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate sample JSON log files')
    parser.add_argument('--output-dir', '-o', default='logs', help='Output directory')
    parser.add_argument('--count', '-c', type=int, default=1000, help='Number of log entries to generate per file')
    parser.add_argument('--continuous', action='store_true', help='Generate logs continuously')
    parser.add_argument('--interval', '-i', type=float, default=1.0, help='Interval between log entries in continuous mode (seconds)')
    parser.add_argument('--no-patterns', action='store_true', help='Exclude anomaly patterns')
    
    args = parser.parse_args()
    
    if args.continuous:
        generate_continuous_logs_multi(args.output_dir, args.interval, not args.no_patterns)
    else:
        generate_log_files(args.output_dir, args.count, not args.no_patterns) 