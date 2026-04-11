# 🔵 SOC Analyst Home Lab — Eyimofe Olaiya

Hands-on SIEM investigations built in a self-configured home lab environment.  
Simulating the alert triage and analysis workflow of a Junior SOC Analyst.

---

## 🛠️ Lab Stack

| Component | Details |
|---|---|
| Hypervisor | VMware Workstation 17 Player |
| SIEM | Splunk Enterprise 9.1.2 (Ubuntu VM) |
| Log Source | Windows 10 VM — Splunk Universal Forwarder (Windows Security logs) |
| Networking | NAT (resolved VMware Player host-only limitation) |

---

## 📁 Investigations

| # | Event ID | Title | Outcome |
|---|---|---|---|
| 1 | 4702 | Scheduled Task Modification | False Positive |
| 2 | 5379 | Credential Manager Read | False Positive |
| 3 | 4625 | Brute Force Attack Detection | True Positive — Alert Fired |

📄 **[Download Full Portfolio (PDF)](./Eyimofe_Olaiya_SOC_Portfolio.pdf)**

---

## 🧠 Skills Demonstrated

- Splunk SIEM configuration and log ingestion
- Windows Security event log analysis and triage
- SPL (Splunk Processing Language) querying
- Alert investigation: query → pivot → correlate → close
- Brute force detection rule engineering
- False positive identification and documentation

---

## 📬 Contact

**Eyimofe Olaiya** — Toronto, Ontario  
[LinkedIn](https://linkedin.com/in/your-link-here) | [GitHub](https://github.com/MofesHub)
