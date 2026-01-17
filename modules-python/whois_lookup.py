#!/usr/bin/env python3
import sys
import os
import re
import json
from datetime import datetime
import whois

def extract_domain(url):
    """Extract domain from URL."""
    domain_regex = r'^(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)'
    match = re.match(domain_regex, url)
    if match:
        return match.group(1)
    return url

def get_date_str(date_value):
    """Convert date to string, handling lists and None."""
    if date_value is None:
        return None
    if isinstance(date_value, list):
        date_value = date_value[0] if date_value else None
    if isinstance(date_value, datetime):
        return date_value.strftime('%Y-%m-%d')
    return str(date_value)

def calculate_age(creation_date):
    """Calculate domain age in days."""
    if creation_date is None:
        return None
    if isinstance(creation_date, list):
        creation_date = creation_date[0] if creation_date else None
    if isinstance(creation_date, datetime):
        delta = datetime.now() - creation_date
        return delta.days
    return None

def get_age_warning(age_days):
    """Return warning if domain is recently registered."""
    if age_days is None:
        return None
    if age_days < 30:
        return "Domain registered < 30 days ago"
    if age_days < 90:
        return "Domain registered < 90 days ago"
    return None

def whois_lookup(domain):
    """Perform WHOIS lookup for a domain."""
    results = {'domain': domain}

    try:
        w = whois.whois(domain)

        results['registrar'] = w.registrar
        results['created'] = get_date_str(w.creation_date)
        results['expires'] = get_date_str(w.expiration_date)
        results['updated'] = get_date_str(w.updated_date)

        age_days = calculate_age(w.creation_date)
        results['age_days'] = age_days
        results['age_warning'] = get_age_warning(age_days)

        # Name servers
        if w.name_servers:
            if isinstance(w.name_servers, list):
                results['name_servers'] = [ns.lower() for ns in w.name_servers]
            else:
                results['name_servers'] = [w.name_servers.lower()]

        # Registrant info (when available)
        if w.org:
            results['organization'] = w.org
        if w.country:
            results['country'] = w.country
        if w.state:
            results['state'] = w.state

        # Status
        if w.status:
            if isinstance(w.status, list):
                results['status'] = w.status
            else:
                results['status'] = [w.status]

    except whois.parser.PywhoisError as e:
        results['error'] = f"WHOIS lookup failed: {str(e)}"
    except Exception as e:
        results['error'] = f"WHOIS lookup failed: {str(e)}"

    return results

def output_yaml(results):
    """Output results in YAML format."""
    print("whois:")
    print(f"  domain: {results.get('domain', 'unknown')}")

    if 'error' in results:
        print(f"  error: {results['error']}")
        print("")
        return

    if results.get('registrar'):
        print(f"  registrar: {results['registrar']}")
    if results.get('created'):
        print(f"  created: {results['created']}")
    if results.get('expires'):
        print(f"  expires: {results['expires']}")
    if results.get('updated'):
        print(f"  updated: {results['updated']}")
    if results.get('age_days') is not None:
        print(f"  age_days: {results['age_days']}")
    if results.get('age_warning'):
        print(f"  age_warning: {results['age_warning']}")
    if results.get('organization'):
        print(f"  organization: {results['organization']}")
    if results.get('country'):
        print(f"  country: {results['country']}")
    if results.get('name_servers'):
        print("  name_servers:")
        for ns in results['name_servers']:
            print(f"    - {ns}")
    if results.get('status'):
        print("  status:")
        for s in results['status']:
            print(f"    - {s}")
    print("")

def output_json(results):
    """Output results in JSON format."""
    print(json.dumps({"whois": results}))

def main():
    if len(sys.argv) < 2:
        print("Usage: python whois_lookup.py <domain_or_url>")
        sys.exit(1)

    url = sys.argv[1]
    domain = extract_domain(url)
    results = whois_lookup(domain)

    output_format = os.environ.get('OUTPUT_FORMAT', 'yaml')
    if output_format == 'json':
        output_json(results)
    else:
        output_yaml(results)

if __name__ == "__main__":
    main()
