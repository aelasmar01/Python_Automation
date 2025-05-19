# CVE Keyword Alert Script

import requests
import json
import csv
import os
import re
from datetime import datetime, timedelta

#Configuration 
# Base URL for NVD's CVE API
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Output file where matched CVEs will be logged
CSV_FILE = "cve_alerts.csv"

# CSV file from which keywords will be read
KEYWORDS_FILE = "keywords.csv"

#Core Functionality

def fetch_recent_cves(api_url, days_back=1):
    """
    Fetch CVEs from the NVD API published within the last `days_back` days.
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
    except Exception as error:
        print(f"Error fetching CVEs: {error}")
        return []

def get_keywords_from_csv(filepath):
    """
    Load keywords from a CSV file where each row contains one keyword.
    Returns a list of keyword strings.
    """
    keywords = []
    try:
        with open(filepath, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if row:  # Ignore empty rows
                    keywords.append(row[0].strip())
    except FileNotFoundError:
        print(f"Keyword file '{filepath}' not found.")
    return keywords

def build_keyword_pattern(keywords):
    """
    Compile a regex pattern that matches any of the given keywords (case-insensitive).
    """
    escaped_keywords = [re.escape(kw) for kw in keywords]
    return re.compile('|'.join(escaped_keywords), re.IGNORECASE)

def filter_cves_by_keywords(cve_list, pattern):
    """
    Filters a list of CVEs to only those whose descriptions match the keyword pattern.
    """
    return [item.get("cve", {}) for item in cve_list if has_matching_description(item.get("cve", {}), pattern)]

def has_matching_description(cve, pattern):
    """
    Check whether any of the CVE's descriptions match the keyword pattern.
    """
    for desc in cve.get("descriptions", []):
        if pattern.search(desc.get("value", "")):
            return True
    return False

def extract_cve_data(cve):
    """
    Extract relevant fields from a CVE object to prepare for CSV export.
    """
    return {
        'CVE ID': cve.get("id", "UNKNOWN"),
        'Published Date': cve.get("published", ""),
        'Description': next((desc.get("value") for desc in cve.get("descriptions", []) if desc.get("lang") == "en"), "")
    }

def write_cves_to_csv(cve_list, filename):
    """
    Append a list of CVE entries to the specified CSV file. Adds headers if the file is new.
    """
    file_exists = os.path.isfile(filename)
    with open(filename, mode='a', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['CVE ID', 'Published Date', 'Description']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()

        for cve in cve_list:
            writer.writerow(extract_cve_data(cve))

def run_alert_workflow():
    """
    Main execution logic:
    1. Load keywords.
    2. Fetch recent CVEs.
    3. Filter for keyword matches.
    4. Log matching CVEs to CSV.
    """
    keywords = get_keywords_from_csv(KEYWORDS_FILE)

    if not keywords:
        print("No keywords found. Exiting.")
        return

    cve_data = fetch_recent_cves(NVD_API_URL, days_back=1)
    keyword_pattern = build_keyword_pattern(keywords)
    filtered_cves = filter_cves_by_keywords(cve_data, keyword_pattern)

    if filtered_cves:
        write_cves_to_csv(filtered_cves, CSV_FILE)
        print(f"{len(filtered_cves)} CVEs written to {CSV_FILE}.")
    else:
        print("No relevant CVEs found today.")

def main():
    #Script entry point.
    run_alert_workflow()

if __name__ == "__main__":
    main()
