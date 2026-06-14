# 🔐 SSH Log Analysis using Splunk

## 📌 Project Overview

This project demonstrates SSH authentication log analysis using Splunk SIEM to detect malicious activity such as brute-force attacks, unauthorized access attempts, and suspicious SSH behavior.

It simulates real-world SOC analyst workflows, including log ingestion, SPL queries, dashboards, and alerting.

## 🎯 Objectives

The project aims to detect and analyze:

- ✅ Successful SSH logins (source and destination analysis)
- ❌ Failed login attempts (password guessing & spraying)
- 🚨 Multiple failed authentication attempts (brute-force indicators)
- 🔍 Connections without authentication (SSH probing or scanning)

---

## 🧪 Lab Setup & Prerequisites

### Prerequisites

- Splunk Enterprise / Splunk Free
- Basic understanding of SPL

### Dataset

- `ssh_log.json` (JSON-formatted SSH authentication logs)

---

## ⚙️ Environment Setup

### Step 1: Log in to Splunk Web

Navigate to:

```text
Apps → Search & Reporting
```

![Search and Reporting](images/setup1.png)

---

### Step 2: Click Add Data

```text
Add Data → Upload
```

![Upload Data](images/setup2.png)

---

### Step 3: Upload Dataset

Upload:

```text
ssh_log.json
```

![Upload JSON File](images/upload.png)

---

### Step 4: Configure Data Input

```text
Source Type : _json
Index       : ssh_logs
```

![Configuration](images/configuration.png)

---

### Step 5: Start Searching

Click **Start Searching** after data ingestion.

![Start Searching](images/start-search.png)

---

# 🧩 Step-by-Step Implementation

## 🔹 Task 1: Log Ingestion & Parsing

### Extracted Fields

- event_type
- auth_success
- auth_attempts
- id.orig_h (Source IP)
- id.resp_h (Destination Host)

### Validation Query

```spl
index=ssh_logs
| stats count by event_type
```

### Purpose

✔ Confirms successful ingestion and parsing.

![Validation Query](images/validation-query.png)

---

## 🔹 Task 2: Failed Login Analysis

### SPL Query

```spl
index=ssh_logs event_type="Failed SSH Login"
| stats count by id.orig_h
| sort - count
| head 10
```

### Visualization

📊 Bar Chart

Failed login attempts per source IP

### Purpose

Identify suspicious IPs attempting credential abuse.

![Failed Login Analysis](images/failed-login-analysis.png)

---

## 🔹 Task 3: Brute-Force Detection

### Multiple Failed Attempts Query

```spl
index=ssh_logs event_type="Multiple Failed Authentication Attempts"
| stats count by id.orig_h, id.resp_h
| where count > 5
```

### Purpose

Detect brute-force attack attempts targeting SSH services.

![Brute Force Detection](images/bruteforce-detection.png)

---

## 🚨 Alert Configuration

### Alert Settings

| Parameter | Value |
|------------|---------|
| Trigger | > 5 failed attempts |
| Time Window | 10 minutes |
| Alert Type | Scheduled / Real-Time |
| Action | SOC notification or email |

### Purpose

Early detection of brute-force attacks.

![Alert Configuration](images/alert-configuration.png)

---

## 📊 Skills Demonstrated

- Splunk SIEM
- SPL Querying
- Security Monitoring
- SSH Log Analysis
- Threat Detection
- Brute-Force Detection
- Alert Configuration
- Incident Investigation
- SOC Operations
- Security Analytics

---

## 📈 Project Outcome

Successfully analyzed SSH authentication logs using Splunk SIEM to identify failed login attempts, brute-force indicators, and suspicious SSH behavior. Created SPL-based detections, visualizations, and alerts to improve security monitoring and incident response capabilities.

---

## 🏷️ Tags

`Splunk`
`SIEM`
`Cybersecurity`
`SOC Analyst`
`Threat Detection`
`SSH Security`
`Security Monitoring`
`Blue Team`
`Log Analysis`
`Brute Force Detection`

---

## 👨‍💻 Author

**Santhosh**

Cybersecurity Analyst | SOC Analyst | Splunk SIEM | Threat Detection
