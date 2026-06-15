<div align="center">

# 🔐 SSH Log Analysis using Splunk

<img width="638" height="193" alt="image" src="https://github.com/user-attachments/assets/0944d89c-51dd-4489-a997-d8c6432a5407" />

![Splunk](https://img.shields.io/badge/SIEM-Splunk-success?style=for-the-badge\&logo=splunk)
![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-blue?style=for-the-badge\&logo=securityscorecard)
![SOC](https://img.shields.io/badge/Role-SOC%20Analyst-purple?style=for-the-badge)
![Status](https://img.shields.io/badge/Project-Completed-brightgreen?style=for-the-badge)

---
</div>

## 📌 Project Overview

This project demonstrates **SSH authentication log analysis** using **Splunk SIEM** to detect malicious activity such as brute-force attacks, unauthorized access attempts, and suspicious SSH behavior.

It simulates **real-world SOC analyst workflows**, including log ingestion, SPL queries, dashboards, and alerting.

---

## 🎯 Objectives

The project aims to detect and analyze:

* ✅ **Successful SSH logins** (source and destination analysis)
* ❌ **Failed login attempts** (password guessing & spraying)
* 🚨 **Multiple failed authentication attempts** (brute-force indicators)
* 🔍 **Connections without authentication** (SSH probing or scanning)

---

## 🧪 Lab Setup & Prerequisites

### Prerequisites

* Splunk Enterprise / Splunk Free
* Basic understanding of SPL

### Dataset

* `ssh_log.json` (JSON-formatted SSH authentication logs)

---

## ⚙️ Environment Setup

1. Log in to **Splunk Web**
2. Navigate to:

   ```
   Apps → Search & Reporting
   ```
   <img width="1919" height="961" alt="1" src="https://github.com/user-attachments/assets/bfe23c11-1ced-485c-aeda-fcbebdb1884a" />
   <img width="1919" height="960" alt="2" src="https://github.com/user-attachments/assets/aaf93941-f97d-49c1-b94a-bf522151ae0e" />

3. Click:

   ```
   Add Data → Upload
   ```
   <img width="1919" height="962" alt="3" src="https://github.com/user-attachments/assets/f7bd6d0c-7785-44cb-a9c0-6fee7c764fa6" />
   <img width="1919" height="962" alt="4" src="https://github.com/user-attachments/assets/ae13ecba-5e1f-4147-86ca-8068947f21b5" />
   <img width="1919" height="963" alt="5" src="https://github.com/user-attachments/assets/b189a10a-db58-4516-8562-f49249d8f791" />

4. Upload `ssh_log.json`
   <img width="1919" height="1079" alt="6" src="https://github.com/user-attachments/assets/b5da78d9-74b2-4a36-b67d-53b697fe5bea" />
   <img width="1919" height="962" alt="7" src="https://github.com/user-attachments/assets/25228885-f399-4ad2-9e3a-c1ba5f16e649" />

5. Configure:

   * **Source type**: `_json`
   * **Index**: `ssh_logs`
  <img width="1919" height="960" alt="8" src="https://github.com/user-attachments/assets/a8876269-7056-40d3-9f15-b45794938893" />
  <img width="1919" height="961" alt="9" src="https://github.com/user-attachments/assets/81bcdb8e-ec79-4f94-8242-f97e6e7abe80" />
  <img width="1919" height="967" alt="10" src="https://github.com/user-attachments/assets/f4a0bb1b-3002-4ae8-96d5-888a3c0ac794" />
  <img width="1919" height="963" alt="11" src="https://github.com/user-attachments/assets/e4f98d5d-b0f7-4510-a546-49024715b53b" />
  <img width="1919" height="960" alt="12" src="https://github.com/user-attachments/assets/9559cb45-0f7f-454d-a3ce-eebaea4143a3" />
  <img width="1919" height="961" alt="13" src="https://github.com/user-attachments/assets/786eb0fc-36b3-40ed-a910-9cd227179c10" />
  <img width="1919" height="965" alt="14" src="https://github.com/user-attachments/assets/41ef4d9a-9f00-4606-9ce7-6f16393c2aac" />

6. Click **Start Searching**
  <img width="1919" height="965" alt="15" src="https://github.com/user-attachments/assets/e56c08a4-6f7c-4c4f-ae79-79792fcf6186" />

---

## 🧩 Step-by-Step Implementation

---

## 🔹 Task 1: Log Ingestion & Parsing

### Extracted Fields

* `event_type`
* `auth_success`
* `auth_attempts`
* `id.orig_h` (Source IP)
* `id.resp_h` (Destination Host)

### Validation Query

```spl
index=ssh_logs
| stats count by event_type
```

✔ Confirms successful ingestion and parsing.
<img width="1919" height="963" alt="16" src="https://github.com/user-attachments/assets/8207c29c-23dd-4be2-b45c-c775a5b6b257" />

---

## 🔹 Task 2: Failed Login Analysis

### SPL Query

```spl
index=ssh_logs event_type="Failed SSH Login"
| stats count by id.orig_h
| sort - count
| head 10
```
<img width="1919" height="963" alt="17" src="https://github.com/user-attachments/assets/54e6cd5a-0e94-4dbc-b72d-72d7822973ed" />
<img width="1919" height="962" alt="18" src="https://github.com/user-attachments/assets/61b3370b-8c39-4f63-895e-9734ef922e2a" />

### Visualization

* 📊 **Bar Chart**
* Failed login attempts per source IP

📌 *Purpose:* Identify suspicious IPs attempting credential abuse.
<img width="1919" height="965" alt="19" src="https://github.com/user-attachments/assets/7f3aeee9-cb17-408f-815f-fe473e5c7ce0" />
<img width="1919" height="964" alt="20" src="https://github.com/user-attachments/assets/025c665f-587f-4c44-8668-9678a7cb038e" />
<img width="1919" height="962" alt="21" src="https://github.com/user-attachments/assets/64349198-b526-4331-ae18-0c8e925e6b25" />

---

## 🔹 Task 3: Brute-Force Detection

### Multiple Failed Attempts Query

```spl
index=ssh_logs event_type="Multiple Failed Authentication Attempts"
| stats count by id.orig_h, id.resp_h
| where count > 5
```
<img width="1919" height="962" alt="22" src="https://github.com/user-attachments/assets/f81b3c72-8616-4217-8ac9-72adea1d31e3" />

### 🚨 Alert Configuration

* Trigger: **> 5 failed attempts**
* Time Window: **10 minutes**
* Alert Type: Scheduled / Real-Time
* Action: SOC notification or email

📌 *Purpose:* Early detection of brute-force attacks.
<img width="1919" height="963" alt="23" src="https://github.com/user-attachments/assets/8543d06a-d6f2-4786-943e-9b1df04feed2" />
<img width="1919" height="963" alt="24" src="https://github.com/user-attachments/assets/2a2ff622-1c1f-4102-8459-e98941a5b779" />
<img width="1919" height="964" alt="25" src="https://github.com/user-attachments/assets/a33d11eb-3a65-4d20-ad83-f5038c94eb2d" />
<img width="1919" height="962" alt="26" src="https://github.com/user-attachments/assets/6fb6f20d-64de-4f82-8741-34ef6192eb37" />
<img width="1919" height="963" alt="27" src="https://github.com/user-attachments/assets/558a7cdf-a5b9-456e-add7-f1080239f532" />
<img width="1919" height="965" alt="28" src="https://github.com/user-attachments/assets/6a5465ed-7baf-423b-94bf-bcd9fea8ba00" />
<img width="1919" height="963" alt="29" src="https://github.com/user-attachments/assets/77c0d0fc-d770-44d1-b046-5ffde771d415" />

---

## 🔹 Task 4: Successful SSH Login Tracking

### SPL Query

```spl
index=ssh_logs event_type="Successful SSH Login"
| stats count by id.orig_h, id.resp_h
```
<img width="1919" height="959" alt="30" src="https://github.com/user-attachments/assets/80ed5cf2-1ac5-4683-86dd-45ae158ede56" />

### Security Correlation

* Compare IPs with prior failed attempts
* Detect possible compromised credentials

📊 **Dashboard Panel**:

* Top source IPs with successful SSH access
<img width="1919" height="963" alt="31" src="https://github.com/user-attachments/assets/925a735f-92a1-41ca-9a24-0d0eb520a24a" />
<img width="1918" height="963" alt="32" src="https://github.com/user-attachments/assets/81353fa4-f3e3-47a7-80f6-b9024ada0345" />
<img width="1919" height="965" alt="33" src="https://github.com/user-attachments/assets/fa419c91-23df-4ede-87b4-be3987ecc34f" />
<img width="1919" height="967" alt="34" src="https://github.com/user-attachments/assets/77920001-c547-4b8e-9102-71ee95d0db7f" />
<img width="1919" height="962" alt="35" src="https://github.com/user-attachments/assets/891a2913-96f1-4706-812c-0b45cd379054" />

---

## 🔹 Task 5: Unauthenticated SSH Connections

### Detection Query

```spl
index=ssh_logs event_type="Connection Without Authentication"
| stats count by id.orig_h
```
<img width="1919" height="963" alt="36" src="https://github.com/user-attachments/assets/be48686c-609f-4b80-8832-a832dbface4d" />

### Time-Based Monitoring

```spl
index=ssh_logs event_type="Connection Without Authentication"
| timechart count by id.orig_h
```
<img width="1919" height="965" alt="37" src="https://github.com/user-attachments/assets/178507eb-c858-4fcb-ba8e-0be76c99b820" />

📌 *Purpose:* Detect reconnaissance, SSH probing, or port scanning.

---

## 📊 Dashboards Implemented

* 🔐 SSH Successful Login Monitoring
* ❌ Failed Authentication Attempts
* 🚨 Brute-Force Detection
* 🔍 Unauthenticated SSH Connection Trends

---

## 🚨 Alerts Implemented

| Alert Name            | Condition          | Time Window |
| --------------------- | ------------------ | ----------- |
| Brute Force Detection | >5 failed attempts | 10 minutes  |

---

## 🧠 Skills Demonstrated

* Splunk SIEM
* SPL Query Writing
* Log Parsing & Analysis
* Brute-force Detection
* Security Monitoring
* SOC Operations

---

## ✅ Project Outcomes

✔ Real-world SOC use cases implemented
✔ Actionable dashboards & alerts created
✔ Improved threat detection capability
✔ Portfolio-ready cybersecurity project

---

## 🚀 Portfolio Value

This project is ideal for showcasing:

* SOC Analyst readiness
* SIEM hands-on experience
* Log-based threat detection skills

---

### 💡 Want to enhance this further?

I can help you add:

* 📸 Dashboard screenshots
* 🧾 Resume bullet points
* 🛡️ Incident response mapping (MITRE ATT&CK)
* 🧩 Splunk alert screenshots
* 🏆 GitHub profile optimization

Just tell me 👍

