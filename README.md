# Lab 3 — RDP Lateral Movement Detection using Splunk

## Overview

This lab demonstrates how an attacker performs lateral movement using Remote Desktop Protocol (RDP) and how such activity can be detected using Windows Security Logs and Sysmon, with analysis performed in Splunk.

The attack flow:

Port Discovery → Credential Attack → RDP Access → Command Execution → Detection

---

## Lab Setup

| Component  | Details                        |
| ---------- | ------------------------------ |
| Attacker   | Kali Linux (192.168.20.11)     |
| Target     | Windows 10 Pro (192.168.20.10) |
| SIEM       | Splunk Enterprise              |
| Monitoring | Sysmon + Windows Logs          |
| Protocol   | RDP (3389)                     |

---

## 1. Port Scanning (RDP Discovery)

```bash
nmap -Pn -p 3389 192.168.20.10
```

![Port Scan](./01.png)

RDP port 3389 is open on the target.

---

## 2. RDP Enabled on Target

RDP is enabled in system settings.

![RDP Enabled](./02.png)

---

## 3. RDP Port Verification

```cmd
netstat -an | find "3389"
```

![Netstat](./03.png)

Port is in LISTENING state.

---

## 4. Initial RDP Connection Attempt (Failure)

```bash
xfreerdp /u:admin /p:Admin123 /v:192.168.20.10
```

![Failed Login](./04.png)

Login fails due to incorrect credentials.

---

## 5. Brute Force / Retry Attempt

Another attempt with different credentials.

![Retry Attempt](./05.png)

Still failing authentication.

---

## 6. Successful RDP Login

Correct credentials used → access granted.

![Successful RDP](./06.png)

Attacker gains remote access.

---

## 7. Interactive Access on Target

Attacker now inside Windows system.

![Inside System](./07.png)

---

## 8. Command Execution

```cmd
whoami
```

![Whoami](./08.png)

Confirms user: admin

---

## 9. Failed Login Logs (Event ID 4625)

Windows logs failed login attempts.

![Event 4625](./09.png)

Key indicators:

* Source IP: 192.168.20.11
* Failure reason: Bad password

---

## 10. Successful Login Logs (Event ID 4624)

![Event 4624](./10.png)

Shows successful RDP login.

---
# Lab 3 — RDP Lateral Movement Detection using Splunk

## Overview

This lab demonstrates how an attacker performs lateral movement using Remote Desktop Protocol (RDP) and how such activity can be detected using Windows Security Logs and Sysmon, with analysis performed in Splunk.

Attack flow:

Port Discovery → Credential Attack → RDP Access → Command Execution → Detection

---

## Lab Setup

| Component  | Details                        |
| ---------- | ------------------------------ |
| Attacker   | Kali Linux (192.168.20.11)     |
| Target     | Windows 10 Pro (192.168.20.10) |
| SIEM       | Splunk Enterprise              |
| Monitoring | Sysmon + Windows Logs          |
| Protocol   | RDP (3389)                     |

---

## 1. Port Scanning (RDP Discovery)

```bash
nmap -Pn -p 3389 192.168.20.10
```

![Port Scan](./01.png)

---

## 2. RDP Enabled on Target

![RDP Enabled](./02.png)

---

## 3. RDP Port Verification

```cmd
netstat -an | find "3389"
```

![Netstat](./03.png)

---

## 4. Initial RDP Attempt (Failure)

![Failed Login](./04.png)

---

## 5. Retry Attempt

![Retry](./05.png)

---

## 6. Successful RDP Login

![Successful Login](./06.png)

---

## 7. Interactive Access

![System Access](./07.png)

---

## 8. Command Execution

```cmd
whoami
```

![Whoami](./08.png)

---

## 9. Failed Login Logs (Event ID 4625)

![Event 4625](./09.png)

---

## 10. Successful Login Logs (Event ID 4624)

![Event 4624](./10.png)

---

## 11. Splunk Analysis (Login Attempts)

```spl
index=endpoint (EventCode=4624 OR EventCode=4625)
| stats count by Source_Network_Address Account_Name EventCode
```

![Splunk Stats](./11.png)

---

## 12. Splunk RDP Detection

```spl
index=endpoint EventCode=4624 Logon_Type=10
| table _time host Account_Name Source_Network_Address Logon_Type
```

![Splunk Detection](./12.png)

---

## Key Findings

* Multiple failed login attempts detected (Event ID 4625)
* Successful RDP login observed from attacker IP
* Source IP: 192.168.20.11
* Remote interactive login (Logon Type 10)
* Attacker gained system access and executed commands
* Splunk successfully identified attack patterns

---

## Conclusion

This lab demonstrates how RDP-based attacks can be detected using:

* Windows Security Logs
* Sysmon (process monitoring)
* Splunk for correlation

Monitoring authentication patterns is critical to detecting unauthorized access.

---

## Skills Demonstrated

* SIEM (Splunk)
* Threat Detection
* Windows Event Analysis
* Log Correlation
* Basic Incident Investigation

## 11. Splunk Log Analysis (Failed + Success)

```spl
index=endpoint (EventCode=4624 OR EventCode=4625)
| stats count by Source_Network_Address Account_Name EventCode
```

![Splunk Stats](./11.png)

---

## 12. Splunk RDP Detection Query

```spl
index=endpoint EventCode=4624 Logon_Type=10
| table _time host Account_Name Source_Network_Address Logon_Type
```

![Splunk RDP](./12.png)

---

## 13. Attack Correlation (Login + Execution)

```spl
index=endpoint (EventCode=4624 OR EventCode=1)
| eval activity=case(EventCode=4624,"RDP Login",EventCode=1,"Command Execution")
| table _time activity host Account_Name Source_Network_Address Image CommandLine
```

![Correlation](./13.png)

---

## 14. Sysmon Process Detection

Sysmon captures command execution.

![Sysmon](./14.png)

Event ID: 1
Process: whoami.exe

---

## Key Findings

* Multiple failed login attempts detected
* Successful RDP login from attacker IP
* Source IP identified as 192.168.20.11
* Attacker gained remote access
* Command execution tracked using Sysmon
* Full attack timeline correlated in Splunk

---

## Conclusion

This lab demonstrates real-world lateral movement via RDP and how defenders can detect it using:

* Windows Event Logs (Authentication)
* Sysmon (Process Monitoring)
* Splunk (Correlation & Detection)

Monitoring failed logins followed by successful access is critical for identifying compromised systems.

---

## Skills Demonstrated

* SIEM (Splunk)
* Threat Detection
* Log Correlation
* Windows Security Monitoring
* Sysmon Analysis
* Attack Simulation
