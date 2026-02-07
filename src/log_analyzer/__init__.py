#!/usr/bin/env python3
"""
GitHub Log Analyzer - Interactive tool for analyzing GitHub activity logs
Supports: API logs, webhook logs, audit logs, and repository events
"""

import json
import re
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple, Optional, Any
import argparse
import sys
import os
from pathlib import Path
from dataclasses import dataclass
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from colorama import init, Fore, Style
import ipywidgets as widgets
from IPython.display import display, HTML, clear_output
import warnings
warnings.filterwarnings('ignore')

# Initialize colorama for colored terminal output
init(autoreset=True)

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
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}

class GitHubLogAnalyzer:
    """Main analyzer class for GitHub logs"""
    
    def __init__(self):
        self.logs = []
        self.df = None
        self.summary_stats = {}
        self.user_agents = Counter()
        self.ip_addresses = Counter()
        
    def load_logs(self, log_file: str, log_type: str = 'auto') -> bool:
        """
        Load logs from various formats
        
        Args:
            log_file: Path to log file
            log_type: Type of log (auto, json, text, csv)
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
            else:
                print(f"{Fore.RED}Unsupported log type: {log_type}")
                return False
                
            self._create_dataframe()
            self._calculate_summary_stats()
            print(f"{Fore.GREEN}Successfully loaded {len(self.logs)} log entries")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}Error loading logs: {e}")
            return False
    
    def _detect_log_type(self, log_file: str) -> str:
        """Auto-detect log file type"""
        ext = Path(log_file).suffix.lower()
        if ext == '.json':
            return 'json'
        elif ext == '.csv':
            return 'csv'
        else:
            # Try to determine by content
            with open(log_file, 'r') as f:
                first_line = f.readline().strip()
                if first_line.startswith('{') or first_line.startswith('['):
                    return 'json'
                elif ',' in first_line and len(first_line.split(',')) > 3:
                    return 'csv'
            return 'text'
    
    def _load_json_logs(self, log_file: str):
        """Load logs from JSON format"""
        with open(log_file, 'r') as f:
            data = json.load(f)
            
        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict) and 'entries' in data:
            entries = data['entries']
        else:
            entries = [data]
        
        for entry in entries:
            try:
                # Parse different JSON log formats
                if 'timestamp' in entry:
                    timestamp = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00'))
                elif 'created_at' in entry:
                    timestamp = datetime.fromisoformat(entry['created_at'].replace('Z', '+00:00'))
                else:
                    continue
                
                username = entry.get('actor', entry.get('user', entry.get('username', 'unknown')))
                repository = entry.get('repo', entry.get('repository', ''))
                event_type = entry.get('type', entry.get('event', 'unknown'))
                action = entry.get('action', '')
                status = entry.get('status', entry.get('response_status', 'unknown'))
                ip_address = entry.get('ip', entry.get('ip_address', ''))
                user_agent = entry.get('user_agent', entry.get('agent', ''))
                
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
                self.ip_addresses[ip_address] += 1
                
            except Exception as e:
                print(f"{Fore.YELLOW}Warning: Could not parse entry: {e}")
    
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
        
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                    
                for pattern in log_patterns:
                    match = re.match(pattern, line)
                    if match:
                        try:
                            timestamp_str = match.group('timestamp')
                            if 'T' in timestamp_str:
                                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                            else:
                                timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
                            
                            log_entry = LogEntry(
                                timestamp=timestamp,
                                username=match.group('username'),
                                repository=match.group('repo') if 'repo' in match.groupdict() else '',
                                event_type=match.group('event') if 'event' in match.groupdict() else 'http',
                                action=match.group('method') if 'method' in match.groupdict() else '',
                                status=match.group('status'),
                                ip_address=match.group('ip'),
                                user_agent='',
                                details={'raw_line': line}
                            )
                            
                            self.logs.append(log_entry)
                            self.ip_addresses[log_entry.ip_address] += 1
                            break
                            
                        except Exception as e:
                            print(f"{Fore.YELLOW}Warning: Could not parse line: {e}")
                            break
    
    def _load_csv_logs(self, log_file: str):
        """Load logs from CSV format"""
        df = pd.read_csv(log_file)
        
        for _, row in df.iterrows():
            try:
                timestamp = pd.to_datetime(row.get('timestamp', row.get('time', datetime.now())))
                
                log_entry = LogEntry(
                    timestamp=timestamp,
                    username=str(row.get('username', row.get('user', 'unknown'))),
                    repository=row.get('repository', row.get('repo', '')),
                    event_type=row.get('event_type', row.get('type', 'unknown')),
                    action=row.get('action', ''),
                    status=str(row.get('status', row.get('response_code', 'unknown'))),
                    ip_address=row.get('ip_address', row.get('ip', '')),
                    user_agent=row.get('user_agent', ''),
                    details=row.to_dict()
                )
                
                self.logs.append(log_entry)
                self.user_agents[log_entry.user_agent] += 1
                self.ip_addresses[log_entry.ip_address] += 1
                
            except Exception as e:
                print(f"{Fore.YELLOW}Warning: Could not parse CSV row: {e}")
    
    def _create_dataframe(self):
        """Convert logs to pandas DataFrame for analysis"""
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
                'date': log.timestamp.date()
            })
        
        self.df = pd.DataFrame(data)
        if not self.df.empty:
            self.df['status_category'] = self.df['status'].apply(self._categorize_status)
    
    def _categorize_status(self, status: str) -> str:
        """Categorize HTTP status codes"""
        try:
            code = int(status)
            if 200 <= code < 300:
                return 'success'
            elif 300 <= code < 400:
                return 'redirect'
            elif 400 <= code < 500:
                return 'client_error'
            else:
                return 'server_error'
        except:
            return 'unknown'
    
    def _calculate_summary_stats(self):
        """Calculate summary statistics"""
        if self.df is None or self.df.empty:
            return
            
        self.summary_stats = {
            'total_requests': len(self.df),
            'unique_users': self.df['username'].nunique(),
            'unique_repos': self.df['repository'].nunique(),
            'unique_ips': self.df['ip_address'].nunique(),
            'time_period': {
                'start': self.df['timestamp'].min(),
                'end': self.df['timestamp'].max(),
                'duration_days': (self.df['timestamp'].max() - self.df['timestamp'].min()).days
            },
            'event_types': dict(self.df['event_type'].value_counts().head(10)),
            'status_distribution': dict(self.df['status_category'].value_counts()),
            'top_users': dict(self.df['username'].value_counts().head(10)),
            'top_repos': dict(self.df['repository'].value_counts().head(10)),
            'top_ips': dict(self.ip_addresses.most_common(10)),
            'hourly_distribution': dict(self.df['hour'].value_counts().sort_index()),
            'busiest_hour': self.df['hour'].mode()[0] if not self.df['hour'].mode().empty else None
        }
    
    def display_summary(self):
        """Display comprehensive summary of logs"""
        if not self.summary_stats:
            print(f"{Fore.YELLOW}No logs loaded or analyzed yet.")
            return
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}{'GITHUB LOG ANALYZER SUMMARY':^60}")
        print(f"{Fore.CYAN}{'='*60}")
        
        print(f"\n{Fore.GREEN}📊 Overall Statistics:")
        print(f"  Total Requests: {self.summary_stats['total_requests']:,}")
        print(f"  Unique Users: {self.summary_stats['unique_users']}")
        print(f"  Unique Repositories: {self.summary_stats['unique_repos']}")
        print(f"  Unique IP Addresses: {self.summary_stats['unique_ips']}")
        
        time_period = self.summary_stats['time_period']
        print(f"\n{Fore.GREEN}⏰ Time Period:")
        print(f"  From: {time_period['start'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  To: {time_period['end'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Duration: {time_period['duration_days']} days")
        
        print(f"\n{Fore.GREEN}📈 Event Distribution:")
        for event, count in self.summary_stats['event_types'].items():
            percentage = (count / self.summary_stats['total_requests']) * 100
            print(f"  {event}: {count:,} ({percentage:.1f}%)")
        
        print(f"\n{Fore.GREEN}✅ Status Code Distribution:")
        for status, count in self.summary_stats['status_distribution'].items():
            percentage = (count / self.summary_stats['total_requests']) * 100
            print(f"  {status}: {count:,} ({percentage:.1f}%)")
        
        print(f"\n{Fore.GREEN}👥 Top Users by Activity:")
        for user, count in self.summary_stats['top_users'].items():
            print(f"  {user}: {count:,} requests")
        
        print(f"\n{Fore.GREEN}🏆 Busiest Hour of Day: Hour {self.summary_stats['busiest_hour']}:00")
        
        print(f"\n{Fore.CYAN}{'='*60}\n")
    
    def plot_timeline(self, save_path: str = None):
        """Plot request timeline"""
        if self.df is None or self.df.empty:
            print(f"{Fore.YELLOW}No data to plot")
            return
            
        daily_counts = self.df.groupby(self.df['timestamp'].dt.date).size()
        
        plt.figure(figsize=(12, 6))
        daily_counts.plot(kind='line', marker='o', color='royalblue', linewidth=2)
        plt.title('GitHub Activity Timeline', fontsize=16, fontweight='bold')
        plt.xlabel('Date', fontsize=12)
        plt.ylabel('Number of Requests', fontsize=12)
        plt.grid(True, alpha=0.3)
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
            print(f"{Fore.GREEN}Timeline plot saved to: {save_path}")
        else:
            plt.show()
    
    def plot_event_distribution(self, save_path: str = None):
        """Plot event type distribution"""
        if self.df is None or self.df.empty:
            print(f"{Fore.YELLOW}No data to plot")
            return
            
        event_counts = self.df['event_type'].value_counts()
        
        plt.figure(figsize=(10, 8))
        colors = plt.cm.Set3(np.linspace(0, 1, len(event_counts)))
        bars = plt.barh(event_counts.index, event_counts.values, color=colors)
        plt.title('Event Type Distribution', fontsize=16, fontweight='bold')
        plt.xlabel('Number of Requests', fontsize=12)
        
        # Add value labels on bars
        for bar in bars:
            width = bar.get_width()
            plt.text(width + max(event_counts.values)*0.01, bar.get_y() + bar.get_height()/2,
                    f'{width:,}', va='center', fontsize=10)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
            print(f"{Fore.GREEN}Event distribution plot saved to: {save_path}")
        else:
            plt.show()
    
    def plot_hourly_activity(self, save_path: str = None):
        """Plot hourly activity pattern"""
        if self.df is None or self.df.empty:
            print(f"{Fore.YELLOW}No data to plot")
            return
            
        hourly_counts = self.df['hour'].value_counts().sort_index()
        
        plt.figure(figsize=(12, 6))
        plt.plot(hourly_counts.index, hourly_counts.values, 
                marker='o', color='coral', linewidth=2, markersize=8)
        plt.fill_between(hourly_counts.index, hourly_counts.values, 
                        alpha=0.3, color='coral')
        plt.title('Hourly Activity Pattern (24h)', fontsize=16, fontweight='bold')
        plt.xlabel('Hour of Day', fontsize=12)
        plt.ylabel('Number of Requests', fontsize=12)
        plt.grid(True, alpha=0.3)
        plt.xticks(range(0, 24))
        plt.xlim(-0.5, 23.5)
        
        # Highlight busiest hour
        busiest_hour = hourly_counts.idxmax()
        busiest_count = hourly_counts.max()
        plt.axvline(x=busiest_hour, color='red', linestyle='--', alpha=0.5)
        plt.text(busiest_hour, busiest_count * 0.9, f'Peak: {busiest_hour}:00', 
                ha='center', fontsize=11, fontweight='bold', color='red')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
            print(f"{Fore.GREEN}Hourly activity plot saved to: {save_path}")
        else:
            plt.show()
    
    def plot_status_codes(self, save_path: str = None):
        """Plot status code distribution"""
        if self.df is None or self.df.empty:
            print(f"{Fore.YELLOW}No data to plot")
            return
            
        status_counts = self.df['status_category'].value_counts()
        
        plt.figure(figsize=(10, 8))
        colors = ['#2ecc71', '#e74c3c', '#f39c12', '#3498db', '#95a5a6']
        explode = [0.1 if i == 0 else 0 for i in range(len(status_counts))]
        
        plt.pie(status_counts.values, labels=status_counts.index, 
                colors=colors[:len(status_counts)], explode=explode,
                autopct='%1.1f%%', startangle=90, shadow=True)
        plt.title('HTTP Status Code Distribution', fontsize=16, fontweight='bold')
        plt.axis('equal')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
            print(f"{Fore.GREEN}Status code plot saved to: {save_path}")
        else:
            plt.show()
    
    def plot_interactive_dashboard(self, save_path: str = None):
        """Create interactive dashboard using Plotly"""
        if self.df is None or self.df.empty:
            print(f"{Fore.YELLOW}No data to plot")
            return
            
        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Activity Timeline', 'Event Distribution', 
                          'Hourly Pattern', 'Status Codes'),
            specs=[[{'type': 'scatter'}, {'type': 'bar'}],
                  [{'type': 'scatter'}, {'type': 'pie'}]]
        )
        
        # Timeline
        daily_counts = self.df.groupby(self.df['timestamp'].dt.date).size()
        fig.add_trace(
            go.Scatter(x=list(daily_counts.index), y=daily_counts.values,
                      mode='lines+markers', name='Requests',
                      line=dict(color='royalblue', width=2)),
            row=1, col=1
        )
        
        # Event distribution
        event_counts = self.df['event_type'].value_counts().head(10)
        fig.add_trace(
            go.Bar(x=event_counts.values, y=event_counts.index,
                   orientation='h', marker_color='lightsalmon',
                   name='Event Types'),
            row=1, col=2
        )
        
        # Hourly pattern
        hourly_counts = self.df['hour'].value_counts().sort_index()
        fig.add_trace(
            go.Scatter(x=hourly_counts.index, y=hourly_counts.values,
                      mode='lines+markers', fill='tozeroy',
                      line=dict(color='coral', width=3),
                      name='Hourly Pattern'),
            row=2, col=1
        )
        
        # Status codes
        status_counts = self.df['status_category'].value_counts()
        fig.add_trace(
            go.Pie(labels=status_counts.index, values=status_counts.values,
                   marker_colors=['#2ecc71', '#e74c3c', '#f39c12', '#3498db']),
            row=2, col=2
        )
        
        # Update layout
        fig.update_layout(
            height=800,
            showlegend=False,
            title_text="GitHub Log Analysis Dashboard",
            title_font_size=20
        )
        
        fig.update_xaxes(title_text="Date", row=1, col=1)
        fig.update_yaxes(title_text="Requests", row=1, col=1)
        fig.update_xaxes(title_text="Count", row=1, col=2)
        fig.update_xaxes(title_text="Hour", row=2, col=1)
        fig.update_yaxes(title_text="Requests", row=2, col=1)
        
        if save_path:
            fig.write_html(save_path)
            print(f"{Fore.GREEN}Interactive dashboard saved to: {save_path}")
        else:
            fig.show()
    
    def detect_anomalies(self, threshold: float = 3.0) -> pd.DataFrame:
        """Detect anomalous activity using statistical methods"""
        if self.df is None or self.df.empty:
            print(f"{Fore.YELLOW}No data for anomaly detection")
            return pd.DataFrame()
        
        # Group by user and calculate statistics
        user_stats = self.df.groupby('username').agg({
            'timestamp': 'count',
            'ip_address': 'nunique',
            'repository': 'nunique'
        }).rename(columns={'timestamp': 'request_count'})
        
        # Calculate z-scores for request counts
        user_stats['request_zscore'] = np.abs(
            (user_stats['request_count'] - user_stats['request_count'].mean()) / 
            user_stats['request_count'].std()
        )
        
        # Find anomalies
        anomalies = user_stats[user_stats['request_zscore'] > threshold]
        
        if not anomalies.empty:
            print(f"{Fore.YELLOW}⚠️  Detected {len(anomalies)} potentially anomalous users:")
            for user, row in anomalies.iterrows():
                print(f"  {Fore.RED}{user}: {row['request_count']} requests "
                      f"(z-score: {row['request_zscore']:.2f})")
        
        return anomalies
    
    def search_logs(self, search_term: str, case_sensitive: bool = False) -> pd.DataFrame:
        """Search through logs for specific terms"""
        if self.df is None or self.df.empty:
            print(f"{Fore.YELLOW}No logs to search")
            return pd.DataFrame()
        
        mask = pd.Series([False] * len(self.df))
        
        # Search in all string columns
        for column in self.df.columns:
            if self.df[column].dtype == 'object':
                if case_sensitive:
                    mask = mask | self.df[column].astype(str).str.contains(search_term)
                else:
                    mask = mask | self.df[column].astype(str).str.contains(search_term, case=False)
        
        results = self.df[mask]
        print(f"{Fore.GREEN}Found {len(results)} matching log entries")
        return results
    
    def export_results(self, format: str = 'csv', filename: str = 'github_log_analysis'):
        """Export analysis results"""
        if self.df is None or self.df.empty:
            print(f"{Fore.YELLOW}No data to export")
            return
        
        if format == 'csv':
            filename = f"{filename}.csv"
            self.df.to_csv(filename, index=False)
            print(f"{Fore.GREEN}Data exported to: {filename}")
        
        elif format == 'json':
            filename = f"{filename}.json"
            export_data = {
                'summary': self.summary_stats,
                'logs': self.df.to_dict('records')
            }
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            print(f"{Fore.GREEN}Data exported to: {filename}")
        
        elif format == 'excel':
            filename = f"{filename}.xlsx"
            with pd.ExcelWriter(filename, engine='openpyxl') as writer:
                self.df.to_excel(writer, sheet_name='Logs', index=False)
                
                # Add summary sheet
                summary_df = pd.DataFrame([self.summary_stats])
                summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            print(f"{Fore.GREEN}Data exported to: {filename}")
        
        else:
            print(f"{Fore.RED}Unsupported export format: {format}")

class InteractiveAnalyzer:
    """Interactive analyzer with menu system"""
    
    def __init__(self):
        self.analyzer = GitHubLogAnalyzer()
        self.running = True
    
    def display_menu(self):
        """Display interactive menu"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}{'GITHUB LOG ANALYZER MENU':^60}")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}1.  Load log file")
        print(f"{Fore.WHITE}2.  Display summary")
        print(f"{Fore.WHITE}3.  Plot timeline")
        print(f"{Fore.WHITE}4.  Plot event distribution")
        print(f"{Fore.WHITE}5.  Plot hourly activity")
        print(f"{Fore.WHITE}6.  Plot status codes")
        print(f"{Fore.WHITE}7.  Show interactive dashboard")
        print(f"{Fore.WHITE}8.  Detect anomalies")
        print(f"{Fore.WHITE}9.  Search logs")
        print(f"{Fore.WHITE}10. Export results")
        print(f"{Fore.WHITE}11. Show all visualizations")
        print(f"{Fore.WHITE}12. Generate HTML report")
        print(f"{Fore.WHITE}0.  Exit")
        print(f"{Fore.CYAN}{'='*60}")
    
    def run(self):
        """Run interactive analyzer"""
        print(f"{Fore.GREEN}🚀 GitHub Log Analyzer - Interactive Mode")
        print(f"{Fore.YELLOW}Supports JSON, CSV, and text log formats")
        
        while self.running:
            self.display_menu()
            
            try:
                choice = input(f"\n{Fore.WHITE}Enter choice (0-12): ").strip()
                
                if choice == '0':
                    self.running = False
                    print(f"{Fore.GREEN}👋 Goodbye!")
                    break
                
                elif choice == '1':
                    log_file = input(f"{Fore.WHITE}Enter log file path: ").strip()
                    if os.path.exists(log_file):
                        log_type = input(f"{Fore.WHITE}Log type (auto/json/csv/text): ").strip() or 'auto'
                        self.analyzer.load_logs(log_file, log_type)
                    else:
                        print(f"{Fore.RED}File not found: {log_file}")
                
                elif choice == '2':
                    self.analyzer.display_summary()
                
                elif choice == '3':
                    save_option = input(f"{Fore.WHITE}Save plot? (y/n): ").strip().lower()
                    if save_option == 'y':
                        filename = input(f"{Fore.WHITE}Enter filename: ").strip() or 'timeline.png'
                        self.analyzer.plot_timeline(filename)
                    else:
                        self.analyzer.plot_timeline()
                
                elif choice == '4':
                    save_option = input(f"{Fore.WHITE}Save plot? (y/n): ").strip().lower()
                    if save_option == 'y':
                        filename = input(f"{Fore.WHITE}Enter filename: ").strip() or 'event_distribution.png'
                        self.analyzer.plot_event_distribution(filename)
                    else:
                        self.analyzer.plot_event_distribution()
                
                elif choice == '5':
                    save_option = input(f"{Fore.WHITE}Save plot? (y/n): ").strip().lower()
                    if save_option == 'y':
                        filename = input(f"{Fore.WHITE}Enter filename: ").strip() or 'hourly_activity.png'
                        self.analyzer.plot_hourly_activity(filename)
                    else:
                        self.analyzer.plot_hourly_activity()
                
                elif choice == '6':
                    save_option = input(f"{Fore.WHITE}Save plot? (y/n): ").strip().lower()
                    if save_option == 'y':
                        filename = input(f"{Fore.WHITE}Enter filename: ").strip() or 'status_codes.png'
                        self.analyzer.plot_status_codes(filename)
                    else:
                        self.analyzer.plot_status_codes()
                
                elif choice == '7':
                    save_option = input(f"{Fore.WHITE}Save dashboard? (y/n): ").strip().lower()
                    if save_option == 'y':
                        filename = input(f"{Fore.WHITE}Enter filename: ").strip() or 'dashboard.html'
                        self.analyzer.plot_interactive_dashboard(filename)
                    else:
                        self.analyzer.plot_interactive_dashboard()
                
                elif choice == '8':
                    threshold = input(f"{Fore.WHITE}Anomaly threshold (default 3.0): ").strip()
                    try:
                        threshold = float(threshold) if threshold else 3.0
                        self.analyzer.detect_anomalies(threshold)
                    except ValueError:
                        print(f"{Fore.RED}Invalid threshold value")
                
                elif choice == '9':
                    search_term = input(f"{Fore.WHITE}Enter search term: ").strip()
                    if search_term:
                        case_sensitive = input(f"{Fore.WHITE}Case sensitive? (y/n): ").strip().lower() == 'y'
                        results = self.analyzer.search_logs(search_term, case_sensitive)
                        if not results.empty:
                            print(f"\n{Fore.CYAN}Search Results:")
                            print(results.head(20).to_string())
                
                elif choice == '10':
                    format_choice = input(f"{Fore.WHITE}Export format (csv/json/excel): ").strip().lower()
                    filename = input(f"{Fore.WHITE}Enter filename (without extension): ").strip()
                    self.analyzer.export_results(format_choice, filename or 'github_log_analysis')
                
                elif choice == '11':
                    self.analyzer.plot_timeline()
                    self.analyzer.plot_event_distribution()
                    self.analyzer.plot_hourly_activity()
                    self.analyzer.plot_status_codes()
                
                elif choice == '12':
                    self.generate_html_report()
                
                else:
                    print(f"{Fore.RED}Invalid choice. Please try again.")
                    
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Operation cancelled.")
                break
            except Exception as e:
                print(f"{Fore.RED}Error: {e}")
    
    def generate_html_report(self):
        """Generate comprehensive HTML report"""
        if self.analyzer.df is None or self.analyzer.df.empty:
            print(f"{Fore.YELLOW}No data for report generation")
            return
        
        # Create temporary plots
        import tempfile
        import base64
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Save plots as images
            timeline_path = os.path.join(tmpdir, 'timeline.png')
            event_path = os.path.join(tmpdir, 'event_dist.png')
            hourly_path = os.path.join(tmpdir, 'hourly.png')
            status_path = os.path.join(tmpdir, 'status.png')
            
            self.analyzer.plot_timeline(timeline_path)
            self.analyzer.plot_event_distribution(event_path)
            self.analyzer.plot_hourly_activity(hourly_path)
            self.analyzer.plot_status_codes(status_path)
            
            # Read images as base64
            def image_to_base64(path):
                with open(path, 'rb') as f:
                    return base64.b64encode(f.read()).decode()
            
            # Generate HTML
            html_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>GitHub Log Analysis Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }}
                    .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
                    .header {{ text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #0366d6; }}
                    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
                    .stat-card {{ background: #f6f8fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #0366d6; }}
                    .stat-value {{ font-size: 24px; font-weight: bold; color: #0366d6; margin: 10px 0; }}
                    .plot-container {{ margin: 30px 0; padding: 20px; background: #f6f8fa; border-radius: 8px; }}
                    .plot {{ max-width: 100%; height: auto; display: block; margin: 0 auto; }}
                    h1 {{ color: #24292e; }}
                    h2 {{ color: #0366d6; border-bottom: 1px solid #e1e4e8; padding-bottom: 10px; }}
                    table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                    th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e1e4e8; }}
                    th {{ background-color: #f6f8fa; }}
                    .timestamp {{ color: #586069; font-size: 0.9em; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>GitHub Log Analysis Report</h1>
                        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    
                    <h2>📊 Summary Statistics</h2>
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div>Total Requests</div>
                            <div class="stat-value">{self.analyzer.summary_stats['total_requests']:,}</div>
                        </div>
                        <div class="stat-card">
                            <div>Unique Users</div>
                            <div class="stat-value">{self.analyzer.summary_stats['unique_users']}</div>
                        </div>
                        <div class="stat-card">
                            <div>Unique Repositories</div>
                            <div class="stat-value">{self.analyzer.summary_stats['unique_repos']}</div>
                        </div>
                        <div class="stat-card">
                            <div>Unique IPs</div>
                            <div class="stat-value">{self.analyzer.summary_stats['unique_ips']}</div>
                        </div>
                    </div>
                    
                    <h2>📈 Activity Timeline</h2>
                    <div class="plot-container">
                        <img src="data:image/png;base64,{image_to_base64(timeline_path)}" class="plot">
                    </div>
                    
                    <h2>🎯 Event Distribution</h2>
                    <div class="plot-container">
                        <img src="data:image/png;base64,{image_to_base64(event_path)}" class="plot">
                    </div>
                    
                    <h2>⏰ Hourly Activity Pattern</h2>
                    <div class="plot-container">
                        <img src="data:image/png;base64,{image_to_base64(hourly_path)}" class="plot">
                    </div>
                    
                    <h2>✅ Status Code Distribution</h2>
                    <div class="plot-container">
                        <img src="data:image/png;base64,{image_to_base64(status_path)}" class="plot">
                    </div>
                    
                    <h2>👥 Top Users</h2>
                    <table>
                        <tr><th>Username</th><th>Requests</th></tr>
                        {"".join(f'<tr><td>{user}</td><td>{count:,}</td></tr>' for user, count in self.analyzer.summary_stats['top_users'].items())}
                    </table>
                    
                    <h2>🔍 Recent Activity</h2>
                    <table>
                        <tr><th>Timestamp</th><th>User</th><th>Event</th><th>Repository</th><th>Status</th></tr>
                        {"".join(f'<tr><td class="timestamp">{row["timestamp"]}</td><td>{row["username"]}</td><td>{row["event_type"]}</td><td>{row["repository"]}</td><td>{row["status"]}</td></tr>' for _, row in self.analyzer.df.head(20).iterrows())}
                    </table>
                </div>
            </body>
            </html>
            """
            
            # Save HTML file
            filename = f"github_log_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            with open(filename, 'w') as f:
                f.write(html_content)
            
            print(f"{Fore.GREEN}HTML report generated: {filename}")
            print(f"{Fore.YELLOW}Open the file in your browser to view the report.")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='GitHub Log Analyzer')
    parser.add_argument('-f', '--file', help='Log file to analyze')
    parser.add_argument('-t', '--type', help='Log type (auto/json/csv/text)', default='auto')
    parser.add_argument('-i', '--interactive', action='store_true', help='Launch interactive mode')
    parser.add_argument('-o', '--output', help='Output format (csv/json/excel/html)', default='html')
    
    args = parser.parse_args()
    
    if args.interactive or not args.file:
        # Launch interactive mode
        analyzer = InteractiveAnalyzer()
        analyzer.run()
    elif args.file:
        # Command-line mode
        analyzer = GitHubLogAnalyzer()
        if analyzer.load_logs(args.file, args.type):
            analyzer.display_summary()
            
            # Generate reports based on output format
            if args.output == 'html':
                # Create HTML report
                interactive = InteractiveAnalyzer()
                interactive.analyzer = analyzer
                interactive.generate_html_report()
            elif args.output in ['csv', 'json', 'excel']:
                analyzer.export_results(args.output)
            else:
                # Show all visualizations
                analyzer.plot_timeline()
                analyzer.plot_event_distribution()
                analyzer.plot_hourly_activity()
                analyzer.plot_status_codes()
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
