# src/config.py
# Configuration for eks-cert-guardian operator

import os

# How often to check certificates (seconds)
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "3600"))  # Default: 1 hour

# Days threshold for warning

WARNING_DAYS = (os.getenv("WARNING_DAYS", "30"))  # Default: 30 days
CRTICAL_DAYS = (os.getenv("CRITICAL_DAYS", "7"))  # Default: 7 days

#ollama configuration
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://192.168.113.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")

#Prometheus metrics port
METRICS_PORT = int(os.getenv("METRICS_PORT", "8000"))

WATCH_NAMESPACE = os.getenv("WATCH_NAMESPACE", "")  # Namespace to watch for certificates
