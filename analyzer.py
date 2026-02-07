#!/usr/bin/env python3
"""
Main analyzer module for GitHub Log Analyzer
"""

import json
import re
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Union
import warnings
warnings.filterwarnings('ignore')


@dataclass
class LogEntry:
    """Data class for structured log entries"""
    timestamp: datetime
    username: str
    repository: str
    event_type: str
    action: str
    status: str
    ip_address: str = ""
    user_agent: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class GitHubLogAnalyzer:
    """Main analyzer class for GitHub logs"""
    
    def __init__(self):
        self.logs: List[LogEntry] = []
        self.df: Optional[pd.DataFrame] = None
        self.summary_stats: Dict[str, Any] = {}
        self.user_agents: Counter = Counter()
        self.ip_addresses: Counter = Counter()
        
    def load_logs(self, log_file: str, log_type: str = 'auto') -> bool:
        """
        Load logs from various formats
        
        Args:
            log_file: Path to log file
            log_type: Type of log (auto, json, text, csv)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if log_type == 'auto':
                log_type = self._detect_log_type(log_file)
                
            if log_type == 'json':
                self._load_json_logs(log_file)
            elif log_type == 'text':
                self._load_text_logs(log_file)
            elif log_type == 'csv':
                self._load_csv_logs(log_file)
            elif log_type == 'ndjson':
                self._load_ndjson_logs(log_file)
            else:
                raise ValueError(f"Unsupported log type: {log_type}")
                
            self._create_dataframe()
            self._calculate_summary_stats()
            return True
            
        except Exception as e:
            raise Exception(f"Error loading logs: {e}")
    
    def _detect_log_type(self, log_file: str) -> str:
        """Auto-detect log file type"""
        from pathlib import Path
        
        ext = Path(log_file).suffix.lower()
        if ext == '.json':
            return 'json'
        elif ext == '.csv':
            return 'csv'
        elif ext == '.ndjson':
            return 'ndjson'
        else:
            # Try to determine by content
            with open(log_file, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()
                if first_line.startswith('{') or first_line.startswith('['):
                    return 'json'
                elif ',' in first_line and len(first_line.split(',')) > 3:
                    return 'csv'
                elif '\t' in first_line and len(first_line.split('\t')) > 3:
                    return 'tsv'
            return 'text'
    
    def _load_json_logs(self, log_file: str):
        """Load logs from JSON format"""
        with open(log_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict) and 'entries' in data:
            entries = data['entries']
        elif isinstance(data, dict) and 'logs' in data:
            entries = data['logs']
        else:
            entries = [data]
        
        for entry in entries:
            try:
                # Parse different JSON log formats
                if 'timestamp' in entry:
                    timestamp_str = entry['timestamp']
                elif 'created_at' in entry:
                    timestamp_str = entry['created_at']
                elif 'time' in entry:
                    timestamp_str = entry['time']
                else:
                    continue
                
                # Parse timestamp
                timestamp = self._parse_timestamp(timestamp_str)
                
                # Extract user information
                username = entry.get('actor', 
                    entry.get('user', 
                    entry.get('username', 
                    entry.get('login', 'unknown'))))
                
                # Extract repository
                repository = entry.get('repo', 
                    entry.get('repository', 
                    entry.get('repo_name', '')))
                
                # Extract event type
                event_type = entry.get('type', 
                    entry.get('event', 
                    entry.get('event_type', 'unknown')))
                
                # Extract action
                action = entry.get('action', 
                    entry.get('operation', ''))
                
                # Extract status
                status = str(entry.get('status', 
                    entry.get('response_status', 
                    entry.get('http_status', 'unknown'))))
                
                # Extract IP address
                ip_address = entry.get('ip', 
                    entry.get('ip_address', 
                    entry.get('client_ip', '')))
                
                # Extract user agent
                user_agent = entry.get('user_agent', 
                    entry.get('agent', 
                    entry.get('user_agent_string', '')))
                
                log_entry = LogEntry(
                    timestamp=timestamp,
                    username=str(username),
                    repository=repository,
                    event_type=event_type,
                    action=action,
                    status=status,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details=entry
                )
                
                self.logs.append(log_entry)
                self.user_agents[user_agent] += 1
                if ip_address:
                    self.ip_addresses[ip_address] += 1
                
            except Exception as e:
                warnings.warn(f"Could not parse entry: {e}")
    
    def _load_ndjson_logs(self, log_file: str):
        """Load logs from Newline Delimited JSON format"""
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    entry = json.loads(line)
                    
                    # Parse timestamp
                    if 'timestamp' in entry:
                        timestamp_str = entry['timestamp']
                    elif '@timestamp' in entry:
                        timestamp_str = entry['@timestamp']
                    else:
                        continue
                    
                    timestamp = self._parse_timestamp(timestamp_str)
                    
                    # Extract fields
                    username = entry.get('user', 
                        entry.get('username', 'unknown'))
                    repository = entry.get('repository', '')
                    event_type = entry.get('event_type', 
                        entry.get('type', 'unknown'))
                    action = entry.get('action', '')
                    status = str(entry.get('status', 'unknown'))
                    ip_address = entry.get('ip_address', '')
                    user_agent = entry.get('user_agent', '')
                    
                    log_entry = LogEntry(
                        timestamp=timestamp,
                        username=str(username),
                        repository=repository,
                        event_type=event_type,
                        action=action,
                        status=status,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        details=entry
                    )
                    
                    self.logs.append(log_entry)
                    self.user_agents[user_agent] += 1
                    if ip_address:
                        self.ip_addresses[ip_address] += 1
                        
                except json.JSONDecodeError:
                    warnings.warn(f"Invalid JSON line: {line[:100]}...")
    
    def _load_text_logs(self, log_file: str):
        """Load logs from plain text/nginx/apache format"""
        log_patterns = [
            # GitHub webhook pattern
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+' \
            r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+' \
            r'(?P<username>\S+)\s+' \
            r'(?P<event>\S+)\s+' \
            r'(?P<repo>\S+)\s+' \
            r'(?P<status>\d{3})',
            
            # Common log format
            r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+' \
            r'-\s+(?P<username>\S+)\s+' \
            r'\[(?P<timestamp>.*?)\]\s+' \
            r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+' \
            r'(?P<status>\d{3})'
        ]
        
        with open(log_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                    
                matched = False
                for pattern in log_patterns:
                    match = re.match(pattern, line)
                    if match:
                        try:
                            timestamp_str = match.group('timestamp')
                            timestamp = self._parse_timestamp(timestamp_str)
                            
                            log_entry = LogEntry(
                                timestamp=timestamp,
                                username=match.group('username'),
                                repository=match.group('repo') if 'repo' in match.groupdict() else '',
                                event_type=match.group('event') if 'event' in match.groupdict() else 'http',
                                action=match.group('method') if 'method' in match.groupdict() else '',
                                status=match.group('status'),
                                ip_address=match.group('ip'),
                                user_agent='',
                                details={'raw_line': line, 'line_number': line_num}
                            )
                            
                            self.logs.append(log_entry)
                            self.ip_addresses[log_entry.ip_address] += 1
                            matched = True
                            break
                            
                        except Exception as e:
                            warnings.warn(f"Could not parse line {line_num}: {e}")
                            break
                
                if not matched:
                    warnings.warn(f"No pattern matched line {line_num}: {line[:100]}...")
    
    def _load_csv_logs(self, log_file: str):
        """Load logs from CSV format"""
        try:
            df = pd.read_csv(log_file)
        except Exception as e:
            raise Exception(f"Failed to read CSV file: {e}")
        
        # Normalize column names
        column_map = {
            'timestamp': ['timestamp', 'time', 'datetime', 'date_time'],
            'username': ['username', 'user', 'actor', 'login'],
            'repository': ['repository', 'repo', 'repo_name'],
            'event_type': ['event_type', 'type', 'event'],
            'action': ['action', 'operation'],
            'status': ['status', 'response_status', 'http_status', 'code'],
            'ip_address': ['ip_address', 'ip', 'client_ip'],
            'user_agent': ['user_agent', 'agent']
        }
        
        actual_columns = {}
        for standard_name, possible_names in column_map.items():
            for name in possible_names:
                if name in df.columns:
                    actual_columns[standard_name] = name
                    break
        
        for _, row in df.iterrows():
            try:
                # Get timestamp
                timestamp_col = actual_columns.get('timestamp')
                if timestamp_col:
                    timestamp = pd.to_datetime(row[timestamp_col])
                else:
                    timestamp = datetime.now()
                
                # Get username
                username_col = actual_columns.get('username')
                username = str(row[username_col]) if username_col else 'unknown'
                
                # Get repository
                repo_col = actual_columns.get('repository')
                repository = row[repo_col] if repo_col else ''
                
                # Get event type
                event_col = actual_columns.get('event_type')
                event_type = row[event_col] if event_col else 'unknown'
                
                # Get action
                action_col = actual_columns.get('action')
                action = row[action_col] if action_col else ''
                
                # Get status
                status_col = actual_columns.get('status')
                status = str(row[status_col]) if status_col else 'unknown'
                
                # Get IP address
                ip_col = actual_columns.get('ip_address')
                ip_address = row[ip_col] if ip_col else ''
                
                # Get user agent
                agent_col = actual_columns.get('user_agent')
                user_agent = row[agent_col] if agent_col else ''
                
                log_entry = LogEntry(
                    timestamp=timestamp,
                    username=username,
                    repository=repository,
                    event_type=event_type,
                    action=action,
                    status=status,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details=row.to_dict()
                )
                
                self.logs.append(log_entry)
                self.user_agents[user_agent] += 1
                if ip_address:
                    self.ip_addresses[ip_address] += 1
                
            except Exception as e:
                warnings.warn(f"Could not parse CSV row: {e}")
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string to datetime object"""
        try:
            # Remove timezone Z and convert to +00:00 format
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str[:-1] + '+00:00'
            
            # Try ISO format first
            try:
                return datetime.fromisoformat(timestamp_str)
            except ValueError:
                pass
            
            # Try common formats
            formats = [
                '%Y-%m-%dT%H:%M:%S.%f%z',
                '%Y-%m-%dT%H:%M:%S%z',
                '%Y-%m-%d %H:%M:%S.%f%z',
                '%Y-%m-%d %H:%M:%S%z',
                '%d/%b/%Y:%H:%M:%S %z',
                '%a %b %d %H:%M:%S %Y',
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
            
            # If all else fails, return current time
            warnings.warn(f"Could not parse timestamp: {timestamp_str}")
            return datetime.now()
            
        except Exception:
            return datetime.now()
    
    def _create_dataframe(self):
        """Convert logs to pandas DataFrame for analysis"""
        if not self.logs:
            self.df = pd.DataFrame()
            return
            
        data = []
        for log in self.logs:
            data.append({
                'timestamp': log.timestamp,
                'username': log.username,
                'repository': log.repository,
                'event_type': log.event_type,
                'action': log.action,
                'status': log.status,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'hour': log.timestamp.hour,
                'day': log.timestamp.day,
                'month': log.timestamp.month,
                'weekday': log.timestamp.weekday(),
                'date': log.timestamp.date(),
                'week': log.timestamp.isocalendar()[1],
                'is_weekend': log.timestamp.weekday() >= 5
            })
        
        self.df = pd.DataFrame(data)
        if not self.df.empty:
            self.df['status_category'] = self.df['status'].apply(self._categorize_status)
    
    def _categorize_status(self, status: str) -> str:
        """Categorize HTTP status codes"""
        try:
            code = int(status)
            if 100 <= code < 200:
                return 'informational'
            elif 200 <= code < 300:
                return 'success'
            elif 300 <= code < 400:
                return 'redirect'
            elif 400 <= code < 500:
                return 'client_error'
            elif 500 <= code < 600:
                return 'server_error'
            else:
                return 'unknown'
        except (ValueError, TypeError):
            return 'unknown'
    
    def _calculate_summary_stats(self):
        """Calculate summary statistics"""
        if self.df is None or self.df.empty:
            self.summary_stats = {}
            return
            
        total_requests = len(self.df)
        
        self.summary_stats = {
            'total_requests': total_requests,
            'unique_users': self.df['username'].nunique(),
            'unique_repos': self.df['repository'].nunique(),
            'unique_ips': self.df['ip_address'].nunique(),
            'time_period': {
                'start': self.df['timestamp'].min(),
                'end': self.df['timestamp'].max(),
                'duration_days': (self.df['timestamp'].max() - self.df['timestamp'].min()).days + 1
            },
            'event_types': dict(self.df['event_type'].value_counts().head(15)),
            'status_distribution': dict(self.df['status_category'].value_counts()),
            'status_codes': dict(self.df['status'].value_counts().head(10)),
            'top_users': dict(self.df['username'].value_counts().head(10)),
            'top_repos': dict(self.df['repository'].value_counts().head(10)),
            'top_ips': dict(self.ip_addresses.most_common(10)),
            'hourly_distribution': dict(self.df['hour'].value_counts().sort_index()),
            'daily_distribution': dict(self.df['date'].value_counts().sort_index()),
            'busiest_hour': int(self.df['hour'].mode()[0]) if not self.df['hour'].mode().empty else None,
            'avg_requests_per_day': total_requests / max(1, self.summary_stats['time_period']['duration_days']),
            'success_rate': (self.df['status_category'] == 'success').sum() / total_requests * 100,
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics"""
        return self.summary_stats.copy()
    
    def get_dataframe(self) -> pd.DataFrame:
        """Get the analyzed data as DataFrame"""
        return self.df.copy() if self.df is not None else pd.DataFrame()
    
    def get_logs(self) -> List[LogEntry]:
        """Get the raw log entries"""
        return self.logs.copy()
    
    def filter_by_date(self, start_date: datetime, end_date: datetime) -> pd.DataFrame:
        """Filter logs by date range"""
        if self.df is None or self.df.empty:
            return pd.DataFrame()
        
        mask = (self.df['timestamp'] >= start_date) & (self.df['timestamp'] <= end_date)
        return self.df[mask].copy()
    
    def filter_by_user(self, username: str) -> pd.DataFrame:
        """Filter logs by username"""
        if self.df is None or self.df.empty:
            return pd.DataFrame()
        
        return self.df[self.df['username'] == username].copy()
    
    def filter_by_repository(self, repository: str) -> pd.DataFrame:
        """Filter logs by repository"""
        if self.df is None or self.df.empty:
            return pd.DataFrame()
        
        return self.df[self.df['repository'] == repository].copy()
    
    def filter_by_event_type(self, event_type: str) -> pd.DataFrame:
        """Filter logs by event type"""
        if self.df is None or self.df.empty:
            return pd.DataFrame()
        
        return self.df[self.df['event_type'] == event_type].copy()
    
    def get_user_statistics(self, username: str) -> Dict[str, Any]:
        """Get statistics for a specific user"""
        if self.df is None or self.df.empty:
            return {}
        
        user_df = self.df[self.df['username'] == username]
        if user_df.empty:
            return {}
        
        return {
            'total_requests': len(user_df),
            'favorite_repository': user_df['repository'].mode()[0] if not user_df['repository'].mode().empty else '',
            'most_common_event': user_df['event_type'].mode()[0] if not user_df['event_type'].mode().empty else '',
            'success_rate': (user_df['status_category'] == 'success').sum() / len(user_df) * 100,
            'activity_by_hour': dict(user_df['hour'].value_counts().sort_index()),
            'repositories': list(user_df['repository'].unique()),
            'first_activity': user_df['timestamp'].min(),
            'last_activity': user_df['timestamp'].max(),
        }
    
    def get_repository_statistics(self, repository: str) -> Dict[str, Any]:
        """Get statistics for a specific repository"""
        if self.df is None or self.df.empty:
            return {}
        
        repo_df = self.df[self.df['repository'] == repository]
        if repo_df.empty:
            return {}
        
        return {
            'total_requests': len(repo_df),
            'top_users': dict(repo_df['username'].value_counts().head(5)),
            'event_distribution': dict(repo_df['event_type'].value_counts()),
            'success_rate': (repo_df['status_category'] == 'success').sum() / len(repo_df) * 100,
            'activity_timeline': dict(repo_df.groupby(repo_df['timestamp'].dt.date).size()),
            'busiest_hour': int(repo_df['hour'].mode()[0]) if not repo_df['hour'].mode().empty else None,
        }
    
    def detect_anomalies(self, threshold: float = 3.0) -> pd.DataFrame:
        """Detect anomalous activity using statistical methods"""
        if self.df is None or self.df.empty:
            return pd.DataFrame()
        
        # Group by user and calculate statistics
        user_stats = self.df.groupby('username').agg({
            'timestamp': 'count',
            'ip_address': 'nunique',
            'repository': 'nunique'
        }).rename(columns={'timestamp': 'request_count'})
        
        # Calculate z-scores for request counts
        mean = user_stats['request_count'].mean()
        std = user_stats['request_count'].std()
        
        if std > 0:
            user_stats['request_zscore'] = np.abs((user_stats['request_count'] - mean) / std)
        else:
            user_stats['request_zscore'] = 0
        
        # Find anomalies
        anomalies = user_stats[user_stats['request_zscore'] > threshold].copy()
        anomalies['anomaly_score'] = anomalies['request_zscore']
        
        return anomalies
    
    def search_logs(self, search_term: str, case_sensitive: bool = False) -> pd.DataFrame:
        """Search through logs for specific terms"""
        if self.df is None or self.df.empty:
            return pd.DataFrame()
        
        mask = pd.Series([False] * len(self.df))
        
        # Search in all string columns
        for column in self.df.columns:
            if self.df[column].dtype == 'object':
                if case_sensitive:
                    column_mask = self.df[column].astype(str).str.contains(search_term, na=False)
                else:
                    column_mask = self.df[column].astype(str).str.contains(search_term, case=False, na=False)
                mask = mask | column_mask
        
        return self.df[mask].copy()
    
    def analyze_trends(self) -> Dict[str, Any]:
        """Analyze trends in the log data"""
        if self.df is None or self.df.empty:
            return {}
        
        # Daily trend
        daily_counts = self.df.groupby(self.df['timestamp'].dt.date).size()
        if len(daily_counts) > 1:
            daily_trend = np.polyfit(range(len(daily_counts)), daily_counts.values, 1)[0]
        else:
            daily_trend = 0
        
        # Hourly pattern correlation
        hourly_pattern = self.df['hour'].value_counts().sort_index()
        
        # Event type trends
        event_trends = {}
        for event_type in self.df['event_type'].unique():
            event_df = self.df[self.df['event_type'] == event_type]
            event_daily = event_df.groupby(event_df['timestamp'].dt.date).size()
            if len(event_daily) > 1:
                trend = np.polyfit(range(len(event_daily)), event_daily.values, 1)[0]
                event_trends[event_type] = trend
        
        return {
            'daily_trend': daily_trend,
            'hourly_pattern': dict(hourly_pattern),
            'event_trends': event_trends,
            'peak_hours': list(hourly_pattern.nlargest(3).index),
            'quiet_hours': list(hourly_pattern.nsmallest(3).index),
        }
