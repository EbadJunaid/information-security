# Hack The Box

This repository contains the methodology and solutions for the **Hack The Box (HTB) Starting Point** machines, completed as part of the Information Security course assignment. 

## Overview
The objective of this project was to gain hands-on experience with fundamental penetration testing concepts, system enumeration, vulnerability assessment, and exploitation in a controlled environment.

## Machines Conquered

### 1. Meow (Linux)
* **Target IP:** 10.129.17.135
* **Vulnerability:** Legacy protocol & Administrative Misconfiguration
* **Exploitation:** Identified an open Telnet service (port 23) using `nmap`. Gained root access by using the default `root` username with a blank password.

### 2. Fawn (Unix/Linux)
* **Target IP:** 10.129.92.191
* **Vulnerability:** Misconfigured FTP Server
* **Exploitation:** Discovered `vsftpd 3.0.3` running on port 21. Exploited an enabled "Anonymous" login with a blank password to access the server and download the flag.

### 3. Dancing (Windows)
* **Target IP:** 10.129.68.39
* **Vulnerability:** Unauthenticated SMB Share
* **Exploitation:** Scanned for open ports and found SMB (port 445). Enumerated shares with `smbclient` and accessed the `WorkShares` directory without a password to retrieve the hidden flag.

### 4. Redeemer (Linux)
* **Target IP:** 10.129.94.136
* **Vulnerability:** Unauthenticated Database Exposed
* **Exploitation:** Conducted a full 65,535 port scan to discover a hidden Redis database on port 6379. Connected directly using `redis-cli` without authentication, navigated the datastore index, and extracted the flag.

## Tools Used
* **Network & Connectivity:** OpenVPN (Hack the Box internal network access)
* **Reconnaissance:** Nmap (Service version detection, aggressive/full-port scanning)
* **Exploitation/Interaction:** Telnet, FTP client, SMBClient, Redis-CLI

For more steps or details, check the [Full Report](bscs22046-infosec-assg-03.pdf).
