# CYT180 — Lab 5: Log Analysis with Pandas, IOCs, and the Mapper Concept
**Weight:** 3% <br>
**Work Type:** Individual <br>
**Submission Format:** Single PDF file containing screenshots from the Jupyter Notebook <br>

----

## Introduction
In this lab, you will apply pandas-based log analysis and the MapReduce mapper concept to SSH authentication logs. You’ll identify and quantify Indicators of Compromise (IOCs), compare activity across two devices, and write a concise SOC‑style analytic summary.
You will analyze two small CSV log files that simulate SSH auth events.
The sample lines include `Invalid user …` and `Failed password …` patterns tied to specific IPs:
- Device A (task_2_logs.csv) shows repeated attempts from 200.30.175.162. [task_2_logs]
- Device B (otherdevice.csv) shows repeated attempts from 220.30.175.162. [otherdevice]
