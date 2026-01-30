# CYT180 — Lab 5: Log Analysis with Pandas, IOCs, and the Mapper Concept
**Weight:** 3% <br>
**Work Type:** Individual <br>
**Submission Format:** Single PDF file containing screenshots from the Jupyter Notebook <br>

----

## Introduction
In this lab you’ll perform IOC‑driven SSH log analysis using pandas and connect your workflow to the MapReduce mapper concept. You will:
- Ingest and filter SSH authentication logs
- Pivot on an indicator of compromise (IOC)
- Count IOC occurrences (pandas and mapper‑style)
- Replicate the workflow on a second device only after you’ve finished Device A
- Write a short SOC‑style analytic summary

The sample data features SSH daemon (sshd) messages with `Invalid user …` and `Failed password …` tied to a specific source IP per device.
- Device A shows attempts from 200.30.175.162 (task_2_logs.csv)
- Device B shows attempts from 220.30.175.162 (otherdevice.csv)
You will verify this through your analysis.

----

## Learning Objectives
By the end of Lab 5, you will be able to:

- Load and sanitize CSV log data with pandas.
- Filter logs by process, IOC, and auth‑failure keywords.
- Explain and apply IOC concepts (why pivoting on IOCs matters).
- Count IOC occurrences using both pandas and a mapper-style loop.
- Compare and correlate findings across two hosts.
- Write a clear SOC‑style analytic summary grounded in evidence.

----

## Background: Indicators of Compromise (IOCs)
- **Definition:** An IOC is a data artifact associated with malicious activity, e.g., suspicious IPs/domains, known malware hashes, or anomalous authentication patterns. In SSH logs, repeated Invalid/Failed attempts from a single source IP often suggest password spraying, credential stuffing, or brute force.
- **IOC pivot:**  After an IOC is identified, analysts pivot: they filter all logs for events involving that IOC, measure scope (how often/where it appears), and decide whether to escalate.
- In these datasets:

  - 200.30.175.162 (Device A) in task_2_logs.csv
  - 220.30.175.162 (Device B) in otherdevice.csv

----

## Dataset Walkthrough
Each CSV includes:
- ProcessID (e.g., sshd[9370])
- Message (the authentication log line)

Examples you’ll see:

- Device A contains lines like:
  - Invalid user admin from 200.30.175.162,
  - Failed password for invalid user fluffy from 200.30.175.162 … `task_2_logs.csv`
- Device B contains lines like:
  - Invalid user admin from 220.30.175.162,
  - Failed password for invalid user slasher from 220.30.175.162

----

## Instructions
Create a new notebook in Google Colab and copy the code step by step, understand the code and inspect the output at each step.
### Task 1 — Load and Inspect the Data
- Import pandas and load the two CSVs:
  ```python
  import pandas as pd

  dfA = pd.read_csv('task_2_logs.csv')
  dfB = pd.read_csv('otherdevice.csv')

  ```
- Show the first 5 rows (head()), column names, and total row counts for each DataFrame.
- In the markdown cell, write 1–2 sentences describing the structure of data and any quirks (e.g., extra spaces).

### Task 2 — Filter for SSH Authentication Events
- Although these files are already SSH-related, write generic filters (so your code is reusable):
  ```python
  import pandas as pd

  sshA = dfA[dfA['ProcessID'].astype(str).str.contains('sshd', na=False)]
  sshB = dfB[dfB['ProcessID'].astype(str).str.contains('sshd', na=False)]
  ```
- How many SSH log lines exist per device?
- Why is filtering by process valuable for triage?

### Task 3 — IOC-Based Suspicious Activity (Device A)
- Set IOC for Device A: 200.30.175.162.
- Filter messages containing the IOC and count occurrences:
  ```python
  ipA = sshA[sshA['Message'].astype(str).str.contains('200.30.175.162', na=False)]
  countA = len(ipA)
  countA
  ```
- Write 2–3 sentences: Is this sufficient evidence of malicious activity? Why or why not?
(Consider that repeated Invalid/Failed attempts are strong signals.)

Context: The sample Device A lines include repeated Invalid/Failed attempts tied to 200.30.175.162. [task_2_logs | Excel]
