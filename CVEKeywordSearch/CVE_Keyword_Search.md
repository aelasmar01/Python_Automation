# CVE Keyword Alert Script

## Purpose and Context

This script monitors newly published CVEs (Common Vulnerabilities and Exposures) from the [National Vulnerability Database (NVD)](https://nvd.nist.gov/) and filters them based on keywords you define.

It solves a common problem in cybersecurity: **manually scanning long CVE lists for technologies you care about**. By automating this task, it reduces analyst workload and improves response time to emerging threats.

**Why this matters:**
- Flags relevant vulnerabilities based on your environment
- Reduces manual triage effort
- Minimizes human error in early threat detection

---

## Real-World Use Case

This script can be scheduled as a **daily job** in:
- Security Operations Centers (SOC)
- Vulnerability management teams
- Red or blue team automation

For example, it can:
- Run every morning via `cron`
- Pull the latest CVEs
- Alert teams to any that match `apache`, `nginx`, or `windows`
- Log matches to a central CSV for action or review

---

## Inputs & Outputs

### Inputs:
- `keywords.csv`: A simple CSV file where **each row contains one keyword** (e.g., `apache`, `nginx`, `microsoft`).
- NVD API: Script connects automatically (no API key required for basic usage).

### Outputs:
- Appends matching CVEs to `cve_alerts.csv`.
- Each row includes:
  - `CVE ID`
  - `Published Date`
  - `Description`

---

## Security and Technical Insights

- Connects over secure HTTPS to the NVD API
- Filters CVEs using an efficient **compiled regular expression**
- Ignores blank or malformed rows in the keyword file
- Handles network/API errors gracefully
- Structured with clean, modular functions for reusability and clarity

---

## Extensibility and Scalability

This script is modular and easily extensible:

- Add Slack, email, or webhook notifications
- Integrate with SIEM or SOAR workflows
- Support CVSS scoring or exploitability ranking
- Convert to JSON output or RESTful microservice

---

## ⚙Setup and Usage

### Requirements:
- Python 3.7+
- Dependency: `requests`

### Installation:

# (Optional) Set up a virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\\Scripts\\activate

# Install required library
pip install requests

Run the Script:
/python cve_keyword_alert.py
Ensure that keywords.csv is present in the same directory as the script.

# Limitations and Future Improvements
Currently checks only CVEs published in the past 24 hours

Does not deduplicate CVEs across runs (append-only behavior)

Only filters based on descriptions — no CVSS or product-level filtering (yet)

Future versions could:

Include severity scoring

Integrate with asset inventories

Add scheduling and alerting options

## Performance Considerations and Time Complexity

The script was designed with scalability in mind, especially considering the potentially large volume of daily CVE data from the NVD API.

### Efficient Keyword Matching with Regex

Instead of performing a nested loop where each keyword is checked individually against every CVE description (which would result in `O(n * k * d)` complexity), we:

- Escape all keywords safely
- Combine them into a single compiled regular expression
- Perform a **single-pass scan** per CVE description using `pattern.search(...)`

This reduces the keyword matching step to approximately `O(n * d)`, where:
- `n` is the number of CVEs returned by the API
- `d` is the average number of descriptions per CVE

### Minimal Overhead in File I/O

- CSV writing is handled in append mode with a one-time check for headers
- Descriptions are extracted in a linear pass using Python’s built-in generators

### Why This Matters

Security automation tools must operate efficiently, especially when integrated into scheduled tasks or larger pipelines. These decisions:

- Ensure the script can scale with daily CVE volumes
- Avoid excessive CPU usage in production environments
- Keep logic clean and maintainable for future enhancements

This optimization enables the script to be extended (e.g., filtering thousands of CVEs or integrating with larger vulnerability datasets) without significant performance loss.
