#
# 🛡️ Network Intrusion Detection System (NIDS)

A Streamlit web application for AI-powered network security analysis and threat detection.

## Features
- Real-time network traffic analysis
- Multiple attack type detection (DoS, Probe, U2R, U2L)
- Anomaly detection using Isolation Forest
- Interactive visualizations with Plotly
- Exportable analysis results

## Deployment
This app is deployed on Streamlit Community Cloud and accessible globally.

## Usage
1. Upload your network traffic CSV file
2. Click "Start Security Analysis"
3. View interactive results and download reports

## Tech Stack
- Streamlit
- Scikit-learn
- Pandas
- Plotly

# Remove the existing virtual environment
rm -rf venv

# Create a new virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Upgrade pip first
pip install --upgrade pip

# Install setuptools and wheel first
pip install setuptools wheel

# Now install the required packages
pip install streamlit pandas numpy scikit-learn matplotlib seaborn plotly joblib
