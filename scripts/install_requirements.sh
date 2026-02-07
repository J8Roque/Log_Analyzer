#!/usr/bin/env bash
set -e

echo "Installing GitHub Log Analyzer..."

# Create virtual environment if missing
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# Upgrade pip
python -m pip install --upgrade pip

# Install everything you listed
pip install pandas numpy matplotlib seaborn plotly colorama ipywidgets faker openpyxl

echo ""
echo "Installation complete!"
echo ""
echo "To activate virtual environment:"
echo "  source .venv/bin/activate"
echo ""
echo "To generate sample logs:"
echo "  python scripts/generate_sample_logs.py"
echo ""
echo "To run the analyzer:"
echo "  python -m log_analyzer.github_log_analyzer -i sample_logs/sample.json"
echo ""
