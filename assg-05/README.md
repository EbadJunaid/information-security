# DFIR Log Analysis Assignment

## Overview
This repository contains the work for the Digital Forensics and Incident Response (DFIR) assignment for Information Security. The objective of this assignment was to analyze system authentication logs to investigate a suspected security breach, reconstruct the attack timeline, and demonstrate an understanding of core digital forensics principles.

## What We Did
The assignment was completed in two main sections:

### Part A: Log Analysis & Timeline Reconstruction
- **Threat Identification:** Analyzed `auth-pre.log` and `auth-post.log` to pinpoint the attacker's IP address (185.130.5.253).
- **Attack Timeline:** Traced the exact time of the unauthorized access resulting from a brute-force attack on the `root` account.
- **Payload & Persistence:** Identified the malicious commands executed by the attacker, specifically the downloading and execution of a malicious script (`backdoor.sh`).
- **Impact Assessment:** Compared normal system activity against the attack timeframe to filter out background noise (false positives) and determine exactly which accounts were compromised.

### Part B: Theoretical & Forensic Questions
- **Chain of Custody:** Explained the critical importance of working on forensic images rather than original, live log files.
- **Log Integrity:** Discussed methods an attacker might use to clear their tracks and how an investigator can detect log tampering.
- **Forensic Tools:** Detailed the use of simple Linux CLI tools (`cat`, `sort`) for merging and chronologically ordering logs.
- **Legal & Ethical Frameworks:** Addressed the legal justification for analyzing system logs under corporate Acceptable Use Policies (AUP).
- **Incident Reporting:** Outlined the 5 essential structural sections of a standard digital forensics investigation report.

## Files Context
- `auth-pre.log`: Logs showing the normal system baseline and authorized user activity.
- `auth-post.log`: Logs capturing the brute-force attack and the subsequent unauthorized commands.
- `manual.pdf`: The original assignment instruction manual.
- `bscs22046-infosec-assg-05` (Google Doc): The final compiled report containing all answers, timelines, and the executive summary.