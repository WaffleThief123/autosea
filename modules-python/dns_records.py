#!/usr/bin/env python3
import sys
import os
import re
import json
import dns.resolver
import dns.exception

def extract_domain(url):
    """Extract domain from URL."""
    domain_regex = r'^(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)'
    match = re.match(domain_regex, url)
    if match:
        return match.group(1)
    return url

def dns_lookup(domain):
    """Query multiple DNS record types for a domain."""
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
    results = {'domain': domain}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                if rtype == 'MX':
                    records.append(f"{rdata.preference} {rdata.exchange}")
                elif rtype == 'SOA':
                    records.append(f"{rdata.mname} {rdata.rname} {rdata.serial}")
                else:
                    records.append(str(rdata).strip('"'))
            results[rtype] = records
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            results['error'] = 'Domain does not exist'
            break
        except dns.exception.Timeout:
            results[rtype] = ['timeout']
        except Exception:
            pass

    return results

def output_yaml(results):
    """Output results in YAML format."""
    print("dns_records:")
    print(f"  domain: {results.get('domain', 'unknown')}")

    if 'error' in results:
        print(f"  error: {results['error']}")
        return

    for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']:
        if rtype in results and results[rtype]:
            print(f"  {rtype}:")
            for record in results[rtype]:
                print(f"    - {record}")
    print("")

def output_json(results):
    """Output results in JSON format."""
    print(json.dumps({"dns_records": results}))

def main():
    if len(sys.argv) < 2:
        print("Usage: python dns_records.py <domain_or_url>")
        sys.exit(1)

    url = sys.argv[1]
    domain = extract_domain(url)
    results = dns_lookup(domain)

    output_format = os.environ.get('OUTPUT_FORMAT', 'yaml')
    if output_format == 'json':
        output_json(results)
    else:
        output_yaml(results)

if __name__ == "__main__":
    main()
