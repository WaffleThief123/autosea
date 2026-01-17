#!/usr/bin/env python3
import sys
import os
import re
import json
import ssl
import socket
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def extract_domain(url):
    """Extract domain from URL."""
    domain_regex = r'^(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)'
    match = re.match(domain_regex, url)
    if match:
        return match.group(1)
    return url

def get_certificate(domain, port=443):
    """Retrieve SSL certificate from domain."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                return cert_der
    except Exception as e:
        return None, str(e)

def parse_certificate(cert_der):
    """Parse certificate and extract relevant info."""
    cert = x509.load_der_x509_certificate(cert_der, default_backend())

    results = {}

    # Issuer
    issuer_parts = []
    for attr in cert.issuer:
        issuer_parts.append(f"{attr.oid._name}={attr.value}")
    results['issuer'] = ', '.join(issuer_parts)

    # Subject
    subject_parts = []
    for attr in cert.subject:
        subject_parts.append(f"{attr.oid._name}={attr.value}")
    results['subject'] = ', '.join(subject_parts)

    # Validity
    results['valid_from'] = cert.not_valid_before_utc.strftime('%Y-%m-%d')
    results['valid_until'] = cert.not_valid_after_utc.strftime('%Y-%m-%d')

    # Days remaining
    now = datetime.utcnow()
    delta = cert.not_valid_after_utc.replace(tzinfo=None) - now
    results['days_remaining'] = delta.days

    # Serial number
    results['serial'] = format(cert.serial_number, 'X')

    # Subject Alternative Names (SANs)
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = []
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(name.value)
            elif isinstance(name, x509.IPAddress):
                sans.append(str(name.value))
        results['san'] = sans
    except x509.ExtensionNotFound:
        results['san'] = []

    return results

def ssl_check(domain):
    """Perform SSL certificate check for a domain."""
    results = {'domain': domain}

    cert_der = get_certificate(domain)

    if cert_der is None:
        results['error'] = 'Failed to retrieve SSL certificate'
        return results

    if isinstance(cert_der, tuple):
        results['error'] = cert_der[1]
        return results

    try:
        cert_info = parse_certificate(cert_der)
        results.update(cert_info)
    except Exception as e:
        results['error'] = f"Failed to parse certificate: {str(e)}"

    return results

def output_yaml(results):
    """Output results in YAML format."""
    print("ssl_certificate:")
    print(f"  domain: {results.get('domain', 'unknown')}")

    if 'error' in results:
        print(f"  error: {results['error']}")
        print("")
        return

    if results.get('issuer'):
        print(f"  issuer: {results['issuer']}")
    if results.get('subject'):
        print(f"  subject: {results['subject']}")
    if results.get('valid_from'):
        print(f"  valid_from: {results['valid_from']}")
    if results.get('valid_until'):
        print(f"  valid_until: {results['valid_until']}")
    if results.get('days_remaining') is not None:
        print(f"  days_remaining: {results['days_remaining']}")
    if results.get('serial'):
        print(f"  serial: {results['serial']}")
    if results.get('san'):
        print("  san:")
        for name in results['san']:
            print(f"    - {name}")
    print("")

def output_json(results):
    """Output results in JSON format."""
    print(json.dumps({"ssl_certificate": results}))

def main():
    if len(sys.argv) < 2:
        print("Usage: python ssl_check.py <domain_or_url>")
        sys.exit(1)

    url = sys.argv[1]
    domain = extract_domain(url)
    results = ssl_check(domain)

    output_format = os.environ.get('OUTPUT_FORMAT', 'yaml')
    if output_format == 'json':
        output_json(results)
    else:
        output_yaml(results)

if __name__ == "__main__":
    main()
