"""
GitHub Log Analyzer - Interactive log analysis tool for GitHub activity logs
"""

__version__ = "1.0.0"
__author__ = "GitHub Log Analyzer Team"
__license__ = "MIT"

from .analyzer import GitHubLogAnalyzer
from .visualizer import (
    plot_timeline,
    plot_event_distribution,
    plot_hourly_activity,
    plot_status_codes,
    create_dashboard,
)
from .utils import (
    load_logs,
    export_results,
    detect_anomalies,
    search_logs,
    generate_report,
)

__all__ = [
    "GitHubLogAnalyzer",
    "plot_timeline",
    "plot_event_distribution",
    "plot_hourly_activity",
    "plot_status_codes",
    "create_dashboard",
    "load_logs",
    "export_results",
    "detect_anomalies",
    "search_logs",
    "generate_report",
]
