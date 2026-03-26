# Lab 3 — Lateral Movement Detection using RDP and Splunk

## Overview

This project simulates a real-world lateral movement attack using Remote Desktop Protocol (RDP) and demonstrates how such activity can be detected using Splunk and Windows logs.

The workflow follows a typical SOC process:

Reconnaissance → Credential Attack → RDP Login → Command Execution → Detection

---

## Objectives

* Simulate RDP-based lateral movement from Kali Linux to Windows
* Generate Windows Security Event Logs (4625, 4624)
* Capture attacker activity using Sysmon (Event ID 1)
* Ingest logs into Splunk
* Detect attacker behavior using SPL queries
* Correlate login activity with command execution

---

## Lab Setup

| Component  | Details                        |
| ---------- | ------------------------------ |
| Attacker   | Kali Linux (192.168.20.11)     |
| Target     | Windows 10 Pro (192.168.20.10) |
| SIEM       | Splunk Enterprise              |
| Monitoring | Sysmon + Windows Event Logs    |
| Protocol   | RDP (Port 3389)                |

---

## Tools Used

* Nmap
* FreeRDP (xfreerdp)
* Splunk Enterprise
* Windows Event Viewer
* Sysmon

---

## Attack Workflow

### 1. Reconnaissance

The attacker scans the target machine to check if RDP is open:

```bash
nmap -Pn -p 3389 192.168.20.10
```

Screenshot:
![Nmap Scan](screenshots/04.png)

---

### 2. RDP Enabled on Target

RDP is enabled on the Windows machine.

Screenshot:
![RDP Enabled](screenshots/01.png)

---

### 3. Port Verification

Confirmed that RDP service is listening on port 3389.

Screenshot:
![Port Listening](screenshots/02.png)

---

### 4. Failed Login Attempts

Attacker attempts multiple incorrect logins using RDP.

Result:

* Event ID 4625 generated
* Failure reason: Unknown user name or bad password

Screenshot:
![Failed Login](screenshots/08.png)

---

### 5. Successful RDP Login

Attacker successfully logs in using valid credentials.

Result:

* Event ID 4624
* Logon Type = 10 (Remote Interactive)

Screenshot:
![Successful Login](screenshots/09.png)

---

### 6. Attacker Command Execution

After gaining access, attacker executes:

```cmd
whoami
```

Captured using Sysmon:

* Event ID 1 (Process Creation)
* Image: whoami.exe
* Parent: cmd.exe

Screenshot:
![Sysmon Whoami](screenshots/12.png)

---

## Splunk Detection

### Failed Login Detection

```spl
index=endpoint EventCode=4625
```

---

### Successful RDP Login Detection

```spl
index=endpoint EventCode=4624 Logon_Type=10
| table _time host Account_Name Source_Network_Address
```

---

### Brute Force Detection

```spl
index=endpoint (EventCode=4624 OR EventCode=4625)
| stats count by Source_Network_Address Account_Name EventCode
```

---

### Command Execution Detection (Sysmon)

```spl
index=endpoint EventCode=1 "whoami"
| table _time User Image CommandLine ParentImage
```

---

### Attack Timeline Correlation

```spl
index=endpoint (EventCode=4624 OR EventCode=1) Account_Name=admin
| eval activity=case(EventCode=4624,"RDP Login",EventCode=1,"Command Execution")
| table _time activity host Account_Name Source_Network_Address Image CommandLine ParentImage
| sort _time
```

---

## Key Findings

* Multiple failed login attempts detected from attacker IP: 192.168.20.11
* Successful RDP login confirmed with Logon Type 10
* Attacker gained interactive access to the system
* Post-login activity captured using Sysmon
* Command execution (whoami) verified attacker presence

---

## Conclusion

This lab demonstrates how attackers use RDP for lateral movement and how defenders can detect:

* Brute-force login attempts
* Successful remote access
* Post-exploitation command execution

By correlating Windows Security logs with Sysmon and analyzing them in Splunk, we can build a complete attack timeline and improve detection capabilities.

---

## Skills Demonstrated

* Threat Detection
* SIEM (Splunk)
* Log Analysis
* Windows Security Monitoring
* Sysmon Analysis
* Attack Simulation (Red + Blue Team)
