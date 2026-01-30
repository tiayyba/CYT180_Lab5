
# CYT180 — Lab 5: Log Analysis with Pandas, IOCs, and the Mapper Concept  
**Weight:** 3%  
**Work Type:** Individual  
**Submission Format:** 2‑Minute Video (see Submission Instructions)

---

----

## Introduction
In this lab, you will perform IOC‑driven SSH log analysis using **pandas** and connect your workflow to the **MapReduce mapper** concept.
You will:

- Ingest and filter SSH authentication logs  
- Pivot on an indicator of compromise (IOC)  
- Count IOC occurrences (using pandas and mapper‑style loops)  
- Replicate your workflow on a second device **only after completing Device A**  
- Write a SOC‑style analytic summary  
- Produce a short (2‑minute) narrated micro‑demo video of your notebook

The sample data includes SSH daemon (`sshd`) messages with **“Invalid user …”** and **“Failed password …”** tied to a suspicious source IP:
- **Device A:** 200.30.175.162 (`task_2_logs.csv`)  
- **Device B:** 220.30.175.162 (`otherdevice.csv`)

----

## Learning Objectives
By the end of Lab 5, you will be able to:


- Load and inspect CSV log data using pandas  
- Filter logs by process (`sshd`), IOC, and authentication‑failure keywords  
- Explain and apply IOC pivoting  
- Count IOC occurrences via both pandas and a mapper pattern  
- Replicate analysis on a second dataset  
- Compare two hosts in a SOC‑style narrative  
- Explain your analysis clearly in a short recorded walkthrough

----


## Background: Indicators of Compromise (IOCs)

- **Definition:** An IOC is any data artifact associated with potential malicious activity.  
  Examples: suspicious IPs/domains, irregular usernames, repeated authentication failures.

- **IOC Pivot:** Once an IOC is identified, analysts “pivot” by filtering logs for all occurrences of that IOC and assessing the scope, frequency, and impact.

- **In this lab:**  
  - Device A IOC: **200.30.175.162**  
  - Device B IOC: **220.30.175.162**

Repeated “Invalid user” or “Failed password” attempts from the same IP may indicate password spraying, credential stuffing, or brute force attempts.

----

## Dataset Walkthrough

Each CSV contains:
- **ProcessID** (e.g., `sshd[9370]`)  
- **Message** (authentication details)

Examples you’ll see:

- Device A (`task_2_logs.csv`)  
  - *Invalid user admin from 200.30.175.162*  
  - *Failed password for invalid user fluffy from 200.30.175.162 port …*

- Device B (`otherdevice.csv`)  
  - *Invalid user admin from 220.30.175.162*  
  - *Failed password for invalid user slasher from 220.30.175.162 port …*

----

## Instructions
Create a new notebook (Google Colab or Jupyter) and follow the tasks step by step.  
Run and inspect the output after each cell.


### **Task 1 — Load and Inspect the Data (Device A)**
- Import pandas and load only **Device A**:
  ```python
  import pandas as pd

  dfA = pd.read_csv('task_2_logs.csv')
  # Quick inspection
  dfA.head()
  dfA.info()
  len(dfA)

  ```
- Write 1–2 sentences describing the dataset structure (column names, number of rows, any quirks like whitespace).
   
### Task 2 — Filter for SSH Authentication Events
- Although these files are already SSH-related, write generic filters (so your code is reusable):
  ```python
  sshA = dfA[dfA['ProcessID'].astype(str).str.contains('sshd', na=False)]
  len(sshA)
  ```
- Answer in Markdown
  - How many SSH log lines exist for Device A?
  - Why is filtering by process name useful as part of triage?
    
### Task 3 — IOC Pivot (Device A) 
- Use the suspected IOC for **Device A: 200.30.175.162**
- Filter messages containing the IOC and count occurrences:
  ```python
  iocA = '200.30.175.162'
  ipA  = sshA[sshA['Message'].astype(str).str.contains(iocA, na=False)]
  len(ipA)
  ipA.head() 
  ```
- In the Markdown, write 2–3 sentences: is this sufficient evidence of malicious activity? Why or why not?

### Task 4 — Failed/Invalid Attempts (Device A)
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
    
### Task 5 — Mapper Concept (Device A)
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
``

    ```

- Answer in Markdown:
  - Explain how this mimics a MapReduce mapper.
  - Why is distributed counting valuable at scale (billions of log lines)?

----
## Task 2B — Step 2: Student‑Driven Analysis of Device B (Do this AFTER Tasks 1–5)
Now you want to do the same analysis for another log file provided `otherdevice.csv`. But before you run the script you need to make some adjustments:
- Change the filename
- Update the IOC
- Rename variables if needed
- Add code comments explaining each change- **Cross‑Host Comparison & SOC Summary**
- Compare Device A vs Device B (IOC frequency, failure counts, notable differences).
- Write a 5–8 sentence SOC‑style summary that answers:
  - Compare IOC frequency (Device A vs Device B)
  - Compare Invalid/Failed authentication counts
  - State what likely occurred
  - Describe whether this resembles brute force, scanning, or something else
  - Provide recommended next steps (blocking, MFA, logging, etc.)
----

## Submission Instructions
- Record a 2-minute video where you show your notebook and explain your analysis verbally.
- The video must include these three checkpoints in order:
- **Checkpoint A — Device A Data Loading (≤ 30 seconds)**
  - Show:
    - dfA.head()
    - Total row count
    - 2-3 sentence explanation of structure (Example: “Here is Device A’s log file. It contains X rows and the columns ProcessID and Message.”)
- **Checkpoint B — IOC & Authentication Failure Filtering (≤ 60 seconds)**
  - IOC filter results for Device A
  - Invalid/Failed filter results for Device A
  - Brief explanation of the counts
- **Checkpoint C — Device B Adjustments & Comparison (≤ 30 seconds)**
  - Results for IOC and failure filtering on Device B
  - Brief explanation of what you changed in code
  - One meaningful difference between Devices A and B

----

## Video Requirements

- Max length: 2 minutes (absolute max 3 minutes; over 3 minutes = 0 marks for the lab)
- Screen share showing your notebook
- Voice narration required along with camera on
- One continuous video capture (no editing)
- Submit as: Unlisted YouTube link
- Paste your video link: in the Blackboard Lab 5 submission
