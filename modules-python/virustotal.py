import sys
import requests
import time

def clear_last_line():
    """Clears the last line in the terminal."""
    sys.stdout.write("\033[F")  # Cursor up one line
    sys.stdout.write("\033[K")  # Clear to the end of line


def VirusTotalCheck(url, vtapi_key):
    headers = {"x-apikey": vtapi_key}
    try:
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        response.raise_for_status()
        vt_analyse = response.json()
        vt_scan_id = vt_analyse['data']['id']

        report_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{vt_scan_id}", headers=headers)
        report_response.raise_for_status()
        vt_report = report_response.json()
    except requests.RequestException as e:
        print(f"VirusTotal API error: {e}")
        sys.exit(1)

    stats = vt_report['data']['attributes']['stats']
    vt_harmless_count = stats.get('harmless', 0)
    vt_undetected_count = stats.get('undetected', 0)
    vt_suspicious_count = stats.get('suspicious', 0)
    vt_malicious_count = stats.get('malicious', 0)
    vt_total = vt_harmless_count + vt_undetected_count + vt_suspicious_count + vt_malicious_count
    vt_positives = vt_suspicious_count + vt_malicious_count

    if vt_total == 0:
        print("VirusTotal: Waiting for additional 20s for results.")
        time.sleep(20)
        clear_last_line()  # Clear the waiting message
        try:
            report_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{vt_scan_id}", headers=headers)
            report_response.raise_for_status()
            vt_report = report_response.json()
        except requests.RequestException as e:
            print(f"VirusTotal API error on retry: {e}")
            sys.exit(1)
        stats = vt_report['data']['attributes']['stats']
        vt_harmless_count = stats.get('harmless', 0)
        vt_undetected_count = stats.get('undetected', 0)
        vt_suspicious_count = stats.get('suspicious', 0)
        vt_malicious_count = stats.get('malicious', 0)
        vt_total = vt_harmless_count + vt_undetected_count + vt_suspicious_count + vt_malicious_count
        vt_positives = vt_suspicious_count + vt_malicious_count

    print("VirusTotal:")
    print(f"    Submitted URL: {url}")
    print(f"    VT Detection Count: {vt_positives}/{vt_total}")
    vt_url = vt_scan_id.split('-')[1]  # Extract ID for URL
    print(f"    VT Link: https://virustotal.com/gui/url/{vt_url}")
    print("")

    # Optionally call VirusTotalDebug here if needed
    # VirusTotalDebug(vt_scan_id, vt_report)

def VirusTotalDebug(vt_scan_id, vt_report):
    stats = vt_report['data']['attributes']['stats']
    print("--------------------------------")
    print("----------DEBUG OUTPUT----------")
    print("--------------------------------")
    print(f"VT SCAN ID: {vt_scan_id}")
    print(f"VT REPORT JSON: {vt_report}")
    print(f"VT UNDETECTED: {stats.get('undetected', 0)}")
    print(f"VT HARMLESS: {stats.get('harmless', 0)}")
    print(f"VT SUSPICIOUS: {stats.get('suspicious', 0)}")
    print(f"VT MALICIOUS: {stats.get('malicious', 0)}")
    print(f"VT TOTAL: {sum(stats.values())}")
    print(f"VT POSITIVES: {stats.get('suspicious', 0) + stats.get('malicious', 0)}")
    print("--------------------------------")

def main():
    if len(sys.argv) < 3:
        print("Usage: python virustotal.py [url] [vtapi_key]")
        sys.exit(1)
    
    url = sys.argv[1]
    vtapi_key = sys.argv[2]
    
    VirusTotalCheck(url, vtapi_key)
    # If you want to explicitly call VirusTotalDebug, adjust accordingly.

if __name__ == "__main__":
    main()
