# CVE Keyword Alert Script

import requests
import csv
import os
from datetime import datetime, timedelta

# --- Configuration ---
# Base URL for NVD's CVE API
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Output file where matched CVEs will be logged
CSV_FILE = "cve_alerts.csv"

# --- Functions ---

def fetch_recent_cves(api_url, days_back=1):
    """
    Fetch recent CVEs from the NVD API, filtering by publication date.
    Returns a list of vulnerability records.
    """
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)
    params = {
        'pubStartDate': start_date.isoformat() + 'Z',
        'pubEndDate': end_date.isoformat() + 'Z',
    }
    try:
        response = requests.get(api_url, params=params)
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"Error fetching CVEs: {e}")
        return []

def filter_cves_by_keywords(cve_list, keywords):
    """
    Filter the full list of CVEs by checking if any keyword
    appears in the CVE's description.
    """
    filtered = []
    for item in cve_list:
        cve = item.get("cve", {})
        if contains_keyword(cve, keywords):
            filtered.append(cve)
    return filtered

def contains_keyword(cve, keywords):
    """
    Check if the CVE's description contains any of the specified keywords.
    Returns True if a match is found.
    """
    descriptions = cve.get("descriptions", [])
    for desc in descriptions:
        text = desc.get("value", "").lower()
        if any(kw.lower() in text for kw in keywords):
            return True
    return False

def get_keywords_from_user():
    """
    Prompt the user to input keywords separated by spaces.
    Returns a list of entered keywords.
    """
    keywords_input = input("Enter keywords separated by spaces: ")
    return keywords_input.split()

def write_cves_to_csv(cve_list, filename):
    """
    Append filtered CVE entries to a CSV file.
    Creates the file and headers if it doesn't exist.
    """
    file_exists = os.path.isfile(filename)
    with open(filename, mode='a', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['CVE ID', 'Published Date', 'Description']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()

        for cve in cve_list:
            cve_id = cve.get("id", "UNKNOWN")
            published = cve.get("published", "")
            description = next((desc.get("value") for desc in cve.get("descriptions", []) if desc.get("lang") == "en"), "")
            writer.writerow({
                'CVE ID': cve_id,
                'Published Date': published,
                'Description': description
            })

def run_alert_workflow():
    """
    Main execution logic: get keywords from user, fetch CVEs,
    filter by keywords, and write results to a CSV file.
    """
    keywords = get_keywords_from_user()

    if not keywords:
        print("No keywords entered. Exiting.")
        return

    cve_data = fetch_recent_cves(NVD_API_URL, days_back=1)
    filtered_cves = filter_cves_by_keywords(cve_data, keywords)

    if filtered_cves:
        write_cves_to_csv(filtered_cves, CSV_FILE)
        print(f"{len(filtered_cves)} CVEs written to {CSV_FILE}.")
    else:
        print("No relevant CVEs found today.")

def main():
    """Entry point for the script."""
    run_alert_workflow()

if __name__ == "__main__":
    main()
