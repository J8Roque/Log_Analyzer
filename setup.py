#!/usr/bin/env python
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="github-log-analyzer",
    version="1.0.0",
    author="GitHub Log Analyzer Team",
    author_email="your-email@example.com",
    description="Interactive log analyzer for GitHub activity logs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/github-log-analyzer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Logging",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "github-log-analyzer=github_log_analyzer.cli:main",
            "gla=github_log_analyzer.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "github_log_analyzer": ["data/*.json"],
    },
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
        "web": [
            "streamlit>=1.24.0",
            "fastapi>=0.100.0",
            "uvicorn>=0.23.0",
        ],
        "notebook": [
            "jupyter>=1.0.0",
            "ipywidgets>=8.0.0",
            "notebook>=6.5.0",
        ],
    },
    keywords="github logs analysis monitoring visualization analytics",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/github-log-analyzer/issues",
        "Source": "https://github.com/yourusername/github-log-analyzer",
        "Documentation": "https://github.com/yourusername/github-log-analyzer/docs",
    },
)
