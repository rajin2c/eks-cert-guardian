# src/k8s_operator.py
# Main kopf operator — watches K8s secrets and runs certificate checks
import kopf
import logging
import asyncio
from prometheus_client import start_http_server
from config import METRICS_PORT, CHECK_INTERVAL, WATCH_NAMESPACE
from kubernetes import client, config as k8s_config
from cert_checker import get_all_tls_secrets, get_ingress_tls


logger = logging.getLogger(__name__)


@kopf.on.startup()
async def startup(settings: kopf.OperatorSettings, **kwargs):
    """Called once when operator starts"""
    logger.info("eks-cert-guardian operator starting up")
    logger.info(f"Check interval: {CHECK_INTERVAL}s")
    logger.info(f"Metrics port: {METRICS_PORT}")
    # Start Prometheus metrics HTTP server
    start_http_server(METRICS_PORT)
    logger.info(f"Metrics server started on port {METRICS_PORT}")

@kopf.timer("", "v1", "secrets", interval=CHECK_INTERVAL)
async def check_certificates_timer(body, name, namespace, **kwargs):
    """Runs every CHECK_INTERVAL seconds — checks all TLS certs."""
    secret_type = body.get("type", "Opaque")
    if secret_type != "kubernetes.io/tls":
        return
    # Load kubeconfig (works locally and inside cluster)
    try:
        k8s_config.load_incluster_config()
    except Exception:
        k8s_config.load_kube_config()  # local development fallback
    v1 = client.CoreV1Api()
    net_v1 = client.NetworkingV1Api()
    # Check all TLS secrets
    tls_results = get_all_tls_secrets(v1)
    ingress_results = get_ingress_tls(net_v1)
    logger.info(f"Checked {len(tls_results)} TLS secrets, {len(ingress_results)} Ingress TLS refs")


@kopf.on.create("", "v1", "secrets")
async def on_secret_created(body, name, namespace, **kwargs):
    """Called when a new Secret is created in the cluster"""
    secret_type = body.get("type", "Opaque")
    if secret_type == "kubernetes.io/tls":
        logger.info(f"New TLS secret detected: {namespace}/{name}")

@kopf.timer("", "v1", "secrets", interval=CHECK_INTERVAL)
async def check_certificates_timer(body, name, namespace, **kwargs):
    """Runs every CHECK_INTERVAL seconds for each TLS secret"""
    secret_type = body.get("type", "Opaque")
    if secret_type != "kubernetes.io/tls":
        return  # Skip non-TLS secrets
    logger.info(f"Checking certificate: {namespace}/{name}")


if __name__ == "__main__":
    kopf.run()

