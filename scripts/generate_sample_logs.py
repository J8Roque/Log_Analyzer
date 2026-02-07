#!/usr/bin/env python3
"""
Generate sample GitHub logs for testing the analyzer
"""

import json
import csv
from datetime import datetime, timedelta
import random
import os
from faker import Faker

fake = Faker()

# GitHub event types and actions
EVENT_TYPES = [
    'push', 'pull_request', 'issues', 'issue_comment', 'create', 'delete',
    'fork', 'watch', 'star', 'release', 'deployment', 'status', 'public',
    'member', 'team', 'organization', 'repository', 'security_advisory'
]

ACTIONS = {
    'push': ['created', 'deleted', 'force_pushed'],
    'pull_request': ['opened', 'closed', 'reopened', 'merged', 'reviewed'],
    'issues': ['opened', 'closed', 'reopened', 'labeled', 'assigned'],
    'issue_comment': ['created', 'edited', 'deleted']
}

REPOSITORIES = [
    'github/explore', 'github/docs', 'github/linguist', 'github/hub',
    'facebook/react', 'vuejs/vue', 'tensorflow/tensorflow', 'microsoft/vscode',
    'torvalds/linux', 'apple/swift', 'rust-lang/rust', 'python/cpython'
]

STATUS_CODES = ['200', '201', '204', '400', '401', '403', '404', '500', '502']

def generate_json_logs(num_entries=1000, output_file='github_logs.json'):
    """Generate sample JSON log file"""
    logs = []
    start_date = datetime.now() - timedelta(days=30)
    
    for i in range(num_entries):
        timestamp = start_date + timedelta(
            seconds=random.randint(0, 30*24*60*60)
        )
        
        event_type = random.choice(EVENT_TYPES)
        action = random.choice(ACTIONS.get(event_type, ['created']))
        
        log_entry = {
            'timestamp': timestamp.isoformat() + 'Z',
            'actor': fake.user_name(),
            'user': fake.user_name(),
            'repository': random.choice(REPOSITORIES),
            'type': event_type,
            'action': action,
            'status': random.choice(STATUS_CODES),
            'ip': fake.ipv4(),
            'user_agent': fake.user_agent(),
            'org': random.choice(['github', 'facebook', 'google', 'microsoft', 'netflix']),
            'location': fake.country_code(),
            'request_id': fake.uuid4(),
            'installation_id': str(random.randint(10000, 99999))
        }
        
        logs.append(log_entry)
    
    # Sort by timestamp
    logs.sort(key=lambda x: x['timestamp'])
    
    with open(output_file, 'w') as f:
        json.dump(logs, f, indent=2)
    
    print(f"Generated {num_entries} JSON log entries in {output_file}")
    return output_file

def generate_csv_logs(num_entries=1000, output_file='github_logs.csv'):
    """Generate sample CSV log file"""
    start_date = datetime.now() - timedelta(days=30)
    
    with open(output_file, 'w', newline='') as f:
        fieldnames = [
            'timestamp', 'username', 'repository', 'event_type', 'action',
            'status', 'ip_address', 'user_agent', 'org', 'location'
        ]
        
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for i in range(num_entries):
            timestamp = start_date + timedelta(
                seconds=random.randint(0, 30*24*60*60)
            )
            
            event_type = random.choice(EVENT_TYPES)
            action = random.choice(ACTIONS.get(event_type, ['created']))
            
            writer.writerow({
                'timestamp': timestamp.isoformat(),
                'username': fake.user_name(),
                'repository': random.choice(REPOSITORIES),
                'event_type': event_type,
                'action': action,
                'status': random.choice(STATUS_CODES),
                'ip_address': fake.ipv4(),
                'user_agent': fake.user_agent(),
                'org': random.choice(['github', 'facebook', 'google', 'microsoft']),
                'location': fake.country_code()
            })
    
    print(f"Generated {num_entries} CSV log entries in {output_file}")
    return output_file

def generate_text_logs(num_entries=1000, output_file='github_logs.txt'):
    """Generate sample text log file (webhook format)"""
    start_date = datetime.now() - timedelta(days=30)
    
    with open(output_file, 'w') as f:
        for i in range(num_entries):
            timestamp = start_date + timedelta(
                seconds=random.randint(0, 30*24*60*60)
            )
            
            event_type = random.choice(EVENT_TYPES)
            
            log_line = (
                f"{timestamp.isoformat()}Z "
                f"{fake.ipv4()} "
                f"{fake.user_name()} "
                f"{event_type} "
                f"{random.choice(REPOSITORIES)} "
                f"{random.choice(STATUS_CODES)}\n"
            )
            
            f.write(log_line)
    
    print(f"Generated {num_entries} text log entries in {output_file}")
    return output_file

if __name__ == '__main__':
    # Generate sample logs in all formats
    print("Generating sample GitHub logs...")
    
    json_file = generate_json_logs(500, 'sample_github_logs.json')
    csv_file = generate_csv_logs(500, 'sample_github_logs.csv')
    text_file = generate_text_logs(500, 'sample_github_logs.txt')
    
    print("\nSample logs generated:")
    print(f"  JSON:  {json_file}")
    print(f"  CSV:   {csv_file}")
    print(f"  Text:  {text_file}")
    print("\nRun the analyzer with: python github_log_analyzer.py -f sample_github_logs.json -i")
