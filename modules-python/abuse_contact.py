#!/usr/bin/env python3
import sys
import os
import re
import json
import socket
import requests

# RDAP bootstrap servers for different RIRs
RDAP_SERVERS = {
    'arin': 'https://rdap.arin.net/registry/ip/',
    'ripe': 'https://rdap.db.ripe.net/ip/',
    'apnic': 'https://rdap.apnic.net/ip/',
    'lacnic': 'https://rdap.lacnic.net/rdap/ip/',
    'afrinic': 'https://rdap.afrinic.net/rdap/ip/',
}

def extract_domain(url):
    """Extract domain from URL."""
    domain_regex = r'^(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)'
    match = re.match(domain_regex, url)
    if match:
        return match.group(1)
    return url

def resolve_domain_to_ip(domain):
    """Resolve domain to IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def query_rdap(ip):
    """Query RDAP servers for IP information."""
    # Try the IANA bootstrap first
    bootstrap_url = f"https://rdap.org/ip/{ip}"

    try:
        response = requests.get(bootstrap_url, timeout=10, allow_redirects=True)
        if response.status_code == 200:
            return response.json()
    except requests.RequestException:
        pass

    # Fallback to individual RIRs
    for rir, server in RDAP_SERVERS.items():
        try:
            response = requests.get(f"{server}{ip}", timeout=10)
            if response.status_code == 200:
                return response.json()
        except requests.RequestException:
            continue

    return None

def extract_abuse_contact(rdap_data):
    """Extract abuse contact information from RDAP response."""
    results = {}

    if not rdap_data:
        return results

    # Network name
    if 'name' in rdap_data:
        results['network'] = rdap_data['name']

    # Handle (network identifier)
    if 'handle' in rdap_data:
        results['handle'] = rdap_data['handle']

    # CIDR
    if 'startAddress' in rdap_data and 'endAddress' in rdap_data:
        results['range'] = f"{rdap_data['startAddress']} - {rdap_data['endAddress']}"

    # Country
    if 'country' in rdap_data:
        results['country'] = rdap_data['country']

    # Extract entities (organizations, contacts)
    if 'entities' in rdap_data:
        for entity in rdap_data['entities']:
            roles = entity.get('roles', [])

            # Look for abuse contact
            if 'abuse' in roles:
                vcard = entity.get('vcardArray', [])
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == 'email':
                            results['abuse_email'] = item[3]
                        if item[0] == 'fn':
                            results['abuse_contact_name'] = item[3]

            # Look for registrant/administrative
            if 'registrant' in roles or 'administrative' in roles:
                vcard = entity.get('vcardArray', [])
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == 'fn' and 'organization' not in results:
                            results['organization'] = item[3]

            # Nested entities
            if 'entities' in entity:
                for nested in entity['entities']:
                    nested_roles = nested.get('roles', [])
                    if 'abuse' in nested_roles:
                        vcard = nested.get('vcardArray', [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == 'email':
                                    results['abuse_email'] = item[3]

    # Remarks may contain abuse info
    if 'remarks' in rdap_data and 'abuse_email' not in results:
        for remark in rdap_data['remarks']:
            if 'description' in remark:
                for desc in remark['description']:
                    if '@' in desc and 'abuse' in desc.lower():
                        # Try to extract email
                        email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', desc)
                        if email_match:
                            results['abuse_email'] = email_match.group(0)
                            break

    return results

def abuse_lookup(ip_or_domain):
    """Perform abuse contact lookup."""
    results = {'query': ip_or_domain}

    # Check if input is an IP or domain
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, ip_or_domain):
        ip = ip_or_domain
    else:
        domain = extract_domain(ip_or_domain)
        ip = resolve_domain_to_ip(domain)
        if ip:
            results['resolved_ip'] = ip
        else:
            results['error'] = f"Could not resolve domain: {domain}"
            return results

    results['ip'] = ip

    rdap_data = query_rdap(ip)
    if not rdap_data:
        results['error'] = "Could not retrieve RDAP data"
        return results

    abuse_info = extract_abuse_contact(rdap_data)
    results.update(abuse_info)

    return results

def output_yaml(results):
    """Output results in YAML format."""
    print("abuse_contact:")
    print(f"  query: {results.get('query', 'unknown')}")

    if 'error' in results:
        print(f"  error: {results['error']}")
        print("")
        return

    if results.get('ip'):
        print(f"  ip: {results['ip']}")
    if results.get('resolved_ip'):
        print(f"  resolved_ip: {results['resolved_ip']}")
    if results.get('network'):
        print(f"  network: {results['network']}")
    if results.get('handle'):
        print(f"  handle: {results['handle']}")
    if results.get('range'):
        print(f"  range: {results['range']}")
    if results.get('organization'):
        print(f"  organization: {results['organization']}")
    if results.get('country'):
        print(f"  country: {results['country']}")
    if results.get('abuse_email'):
        print(f"  abuse_email: {results['abuse_email']}")
    if results.get('abuse_contact_name'):
        print(f"  abuse_contact_name: {results['abuse_contact_name']}")
    print("")

def output_json(results):
    """Output results in JSON format."""
    print(json.dumps({"abuse_contact": results}))

def main():
    if len(sys.argv) < 2:
        print("Usage: python abuse_contact.py <ip_or_domain_or_url>")
        sys.exit(1)

    target = sys.argv[1]
    results = abuse_lookup(target)

    output_format = os.environ.get('OUTPUT_FORMAT', 'yaml')
    if output_format == 'json':
        output_json(results)
    else:
        output_yaml(results)

if __name__ == "__main__":
    main()
