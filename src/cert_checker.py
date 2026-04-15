# src/cert_checker.py
# Checks certificate expiry from K8s TLS secrets and Ingress resources

import base64
import datetime
import logging
from typing import Dict, List

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from kubernetes import client

logger = logging.getLogger(__name__)


def parse_cert_expiry(cert_pem_bytes: bytes) -> int:
    """Parse a PEM certificate and return days until expiry."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem_bytes, default_backend())
        now = datetime.datetime.now(datetime.timezone.utc)
        expiry = cert.not_valid_after_utc
        delta = expiry - now
        return delta.days
    except Exception as e:
        logger.error(f"Failed to parse certificate: {e}")
        return -1  # Return -1 to signal parse error


def check_tls_secret(name: str, namespace: str, secret_data: dict) -> Dict:
    """Check a single TLS secret and return expiry info."""
    result = {
        "name": name,
        "namespace": namespace,
        "type": "tls-secret",
        "days_until_expiry": -1,
        "error": None,
    }
    try:
        if "tls.crt" not in secret_data:
            result["error"] = "No tls.crt found in secret"
            return result
        cert_pem = base64.b64decode(secret_data["tls.crt"])
        result["days_until_expiry"] = parse_cert_expiry(cert_pem)
        if result["days_until_expiry"] == -1:
            result["error"] = "Failed to parse certificate"
    except Exception as e:
        result["error"] = str(e)
    return result


def get_all_tls_secrets(v1_client: client.CoreV1Api) -> List[Dict]:
    """List all TLS secrets across all namespaces and check their expiry."""
    results = []
    try:
        secrets = v1_client.list_secret_for_all_namespaces(
            field_selector="type=kubernetes.io/tls"
        )
        for secret in secrets.items:
            result = check_tls_secret(
                name=secret.metadata.name,
                namespace=secret.metadata.namespace,
                secret_data=secret.data or {},
            )
            results.append(result)
            logger.info(
                f"Cert: {result['namespace']}/{result['name']} - {result['days_until_expiry']} days"
            )
    except Exception as e:
        logger.error(f"Failed to list TLS secrets: {e}")
    return results


def get_ingress_tls(networking_client: client.NetworkingV1Api) -> List[Dict]:
    """List all Ingress resources and extract TLS secret references."""
    results = []
    try:
        ingresses = networking_client.list_ingress_for_all_namespaces()
        for ingress in ingresses.items:
            if not ingress.spec.tls:
                continue
            for tls in ingress.spec.tls:
                if not tls.secret_name:
                    logger.warning(
                        "Ingress %s/%s has a TLS entry without a secret name; skipping",
                        ingress.metadata.namespace,
                        ingress.metadata.name,
                    )
                    continue
                results.append(
                    {
                        "name": tls.secret_name,
                        "namespace": ingress.metadata.namespace,
                        "type": "ingress-tls",
                        "ingress_name": ingress.metadata.name,
                        "hosts": tls.hosts or [],
                    }
                )
    except Exception as e:
        logger.error(f"Failed to list Ingress TLS: {e}")
    return results
