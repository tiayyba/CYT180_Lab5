# CYT180 — Lab 5: Log Analysis with Pandas, IOCs, and the Mapper Concept
**Weight:** 3% <br>
**Work Type:** Individual <br>
**Submission Format:** 2-3 minutes video, see submission instructions.

----

## Introduction
In this lab you’ll perform IOC‑driven SSH log analysis using pandas and connect your workflow to the MapReduce mapper concept.<br>
You will:
- Ingest and filter SSH authentication logs
- Pivot on an indicator of compromise (IOC)
- Count IOC occurrences (pandas and mapper‑style)
- Replicate the workflow on a second device only after you’ve finished Device A
- Write a short SOC‑style analytic summary

The sample data features SSH daemon (sshd) messages with `Invalid user …` and `Failed password …` tied to a specific source IP per device.<br>
  - Device A shows attempts from 200.30.175.162 (deviceA_ssh_logs.csv)
  - Device B shows attempts from 220.30.175.162 (deviceB_ssh_logs.csv) <br>

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

In cybersecurity, an Indicator of Compromise (IOC) is simply a clue that something suspicious or malicious may be happening on a system. An IOC is a specific piece of data that stands out during an investigation—something that doesn’t typically appear in normal system activity.
Common IOC types include:
- A suspicious IP address repeatedly trying to log in
- A filename, hash, or registry value associated with known malware
- An unusual domain or URL contacting a server at odd hours

**Why IOCs matter:** Logs often contain thousands or millions of entries. An IOC gives analysts a starting point:
“I found this suspicious thing... now show me everything else related to it.”

**IOC Pivoting:** Pivoting means filtering and reorganizing logs around the suspicious item. It’s like clicking a person’s username on social media to see all their posts.
You take one clue and explore every event connected to it.
In this lab, the IOC is a source IP address sending repeated failed login attempts to an SSH server. This is significant because legitimate users almost never generate dozens of login failures across many usernames.

**Why these IPs matter in this dataset:**
You will pivot on these two IOCs:
- 200.30.175.162 (Device A)
- 220.30.175.162 (Device B)

These IP addresses are repeatedly associated with:

- Invalid user ...
- Failed password ...
  
Such patterns are common in SSH brute‑force or password‑spray attacks.

**Cross‑Host IOC Correlation:**
Attackers often use the **same source IP** against many systems.
This is why analysts check:
- Does the IOC appear on multiple devices?
- Is the behavior similar across hosts?

If the same IP is attempting many invalid logins on multiple machines, it may indicate a broader campaign rather than an isolated issue.

----


## Dataset Walkthrough
You are provided with two data files.
- deviceA_ssh_logs.csv
- deviceB_ssh_logs.csv

Each CSV includes:
- ProcessID (e.g., sshd[9370])
- Message (the authentication log line)

Examples you’ll see:

- Device A contains lines like:
  - Invalid user admin from 200.30.175.162, (This is the IOC (source IP))
  - Failed password for invalid user fluffy from 200.30.175.162 …
- Device B contains lines like:
  - Invalid user admin from 220.30.175.162,
  - Failed password for invalid user slasher from 220.30.175.162
----

## Part A — IOC‑Driven Analysis on Device A (deviceA_ssh_logs.csv)
Create a new notebook in Google Colab and copy the code step by step, understand the code and inspect the output at each step.

### Step 1 — Load and Inspect the Data
- Import pandas and load only **Device A**:
  ```python
  import pandas as pd

  dfA = pd.read_csv('deviceA_ssh_logs.csv')
  # Quick inspection
  dfA.head()
  dfA.info()
  len(dfA)

  ```
- In the markdown cell, write 1–2 sentences describing the structure of data and any quirks (e.g., extra spaces).
  
### Step 2 — Filter for SSH Authentication Events
- Although these files are already SSH-related, write generic filters (so your code is reusable):
  ```python
  sshA = dfA[dfA['ProcessID'].astype(str).str.contains('sshd', na=False)]
  len(sshA)
  ```
- Answer in Markdown
  - How many SSH log lines exist?
  - Why is filtering by process valuable for triage?

### Step 3 — IOC Pivot (Device A) 
- Use the suspected IOC for **Device A: 200.30.175.162**
- Filter messages containing the IOC and count occurrences:
  ```python
  iocA = '200.30.175.162'
  ipA  = sshA[sshA['Message'].astype(str).str.contains(iocA, na=False)]
  len(ipA)
  ipA.head() 
  ```
- In the Markdown, write 2–3 sentences: is this sufficient evidence of malicious activity? Why or why not?

### Step 4 — Failed/Invalid Attempts (Device A)
- Search for common failure indicators:
  ```python
  keywords = ['Invalid', 'Failed']
  pattern  = '|'.join(keywords)

  failA = ipA[ipA['Message'].astype(str).str.contains(pattern, na=False)]
  len(failA)
  failA
  ```
- Answer in Markdown:
  - How many suspicious authentication failures are present for Device A?
  - What patterns do you notice (usernames, ports, repetition)?
    
### Step 5 — Mapper Concept (Device A)
- Demonstrate a mapper‑like tokenization (word count idea):
  ```python
  # Mapper-like emission: (token, 1)
  for line in dfA['Message']:
      line = line.strip()  # Remove leading/trailing whitespaces from the line
      words = line.split()  # Split the line into words based on whitespace
      for word in words:  # Iterate over each word in the line
         # Print the word followed by a space and '1'
          print(word, "1")
   ```

- Now count exact IOC tokens (Device A):

  ```python
    count_tokens_A = 0
    for line in dfA['Message']:
        for word in str(line).split():
            if word == iocA:
                count_tokens_A += 1
    print(f"Total occurrences of {iocA}: {count_tokens_A}")

    ```

- Answer in Markdown:
  - Explain how this mimics a MapReduce mapper.
  - Why is distributed counting valuable at scale (billions of log lines)?

----

## Part B — IOC‑Driven Analysis on Device B (deviceB_ssh_logs.csv)
Now that you’ve completed Tasks 1–5 for Device A, you will repeat the same IOC‑driven log analysis on a second host: Device B.
The goal of this part is to help you practice pivoting on a new IOC, adapting your code, and comparing patterns across multiple systems, exactly what a SOC analyst does when checking if an attack is isolated or part of a broader campaign.

This section is intentionally less guided: your task is to take what you built in Part A and apply it independently to a second host.

Using the workflow you created for Device A, independently perform the same full analysis on Device B. Your job is to adapt your own code from Part A to this new dataset, including updating the IOC, adjusting any file‑specific logic, and ensuring that your Device A and Device B results remain separate.

Once your analysis is complete, compare your findings from both devices. Discuss differences in IOC activity, authentication failures, username patterns, and any indications of scanning or brute‑force behavior across hosts. Conclude with a short SOC‑style analytic summary describing what occurred on each system, the evidence that supports your conclusions, and recommended next steps for incident response.

**Cross‑Host Comparison & SOC Summary**
  - Compare Device A vs Device B (IOC frequency, failure counts, notable differences).
  - Write a 5–8 sentence SOC‑style summary in markdown that answers:
    - What happened?
    - What evidence supports your conclusion?
    - Does this look like a brute‑force/scanning campaign?
    - Whether both devices show similar or coordinated activity
    - What next steps would you recommend (e.g., blocking, MFA enforcement, log retention, alerting thresholds)?

----

## Submission Instructions
- Record a 2-minute 30 seconds video where you show your notebook and explain your analysis verbally.
- The video must include these four checkpoints in order:
- **Checkpoint A — Device A Data Loading (≤ 30 seconds)**
  - Demonstrate loading deviceA_ssh_logs.csv
  - The total number of rows
  - A brief verbal explanation of the dataset structure. (Example: “Here is Device A’s log file. It contains X rows and the columns ProcessID and Message.”)
- **Checkpoint B — IOC & Authentication Failure Filtering (≤ 60 seconds)**
  - Show the IOC filter results for Device A
  - Invalid/Failed filter results for Device A
  - A short verbal interpretation of the counts and what they suggest. (Example: “This IP appears repeatedly with Failed and Invalid login attempts, which is suspicious.”)
- **Checkpoint C — Device B Adjustments & Comparison (≤ 30 seconds)**
  - Results for IOC and failure filtering on Device B
  - Brief explanation of what you changed in code
  - One meaningful difference between Devices A and B
- **Checkpoint D — Cross‑Host Comparison & SOC Summary (≤ 30 seconds)**
  - Speak a short, verbal SOC summary that includes:
    - One clear difference between Device A and Device B
    - Whether the behavior looks like brute‑force or scanning
    - Whether both devices show similar or coordinated activity
      
----

## Video Requirements

- Max length: 2 minutes 30 seconds (absolute max 3 minutes; over 3 minutes = 0 marks for the lab)
- Screen share showing your notebook
- Voice narration required along with camera on
- One continuous video capture (no editing)
- Submit as: Unlisted YouTube link
- Paste your video link: in the Blackboard Lab 5 submission
