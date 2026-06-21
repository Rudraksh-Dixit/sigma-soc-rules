# Sigma SOC Rules

> **Custom Sigma detection rules for SOC analysts. Written from real TTPs, tested with Atomic Red Team.**
> 15 rules covering persistence, lateral movement, credential access, defense evasion, C2, and exfiltration.

## What is this?

A collection of production-quality Sigma detection rules I wrote, tested, and tuned. Each rule targets a specific MITRE ATT&CK technique, includes false positive considerations, and was validated using Atomic Red Team simulations in a live Wazuh/ELK SOC lab.

This is not a copy-paste of the Sigma public repo. Every rule here was written by analyzing real adversary behavior — encoded PowerShell, LSASS dumping via procdump, certutil living-off-the-land, WMI lateral movement, and more.

## Rule Index

| # | Rule | MITRE ATT&CK | Severity |
|---|------|-------------|----------|
| 1 | [Suspicious PowerShell - Encoded Command](./rules/windows/process_creation/susp_encoded_powershell.yml) | T1059.001 | High |
| 2 | [LSASS Access via Procdump](./rules/windows/process_creation/susp_lsass_procdump.yml) | T1003.001 | Critical |
| 3 | [Certutil Download](./rules/windows/process_creation/susp_certutil_download.yml) | T1105 | High |
| 4 | [Scheduled Task Persistence](./rules/windows/process_creation/susp_schtasks_persistence.yml) | T1053.005 | Medium |
| 5 | [Registry Run Key Modification](./rules/windows/registry/reg_run_key_persistence.yml) | T1547.001 | High |
| 6 | [WMI Lateral Movement](./rules/windows/process_creation/susp_wmi_lateral.yml) | T1047 | High |
| 7 | [PsExec Service Creation](./rules/windows/process_creation/susp_psexec_service.yml) | T1021.006 | High |
| 8 | [BITSAdmin Download](./rules/windows/process_creation/susp_bitsadmin_download.yml) | T1197 | Medium |
| 9 | [MSHTA Suspicious Execution](./rules/windows/process_creation/susp_mshta_exec.yml) | T1218.005 | High |
| 10 | [Rundll32 Suspicious Invocation](./rules/windows/process_creation/susp_rundll32_exec.yml) | T1218.011 | High |
| 11 | [Net User Discovery](./rules/windows/process_creation/susp_net_user_enum.yml) | T1087.001 | Low |
| 12 | [Suspicious Service Installation](./rules/windows/process_creation/susp_service_install.yml) | T1543.003 | High |
| 13 | [DNS Query to Suspicious TLD](./rules/windows/network_connection/susp_dns_suspicious_tld.yml) | T1071.001 | Medium |
| 14 | [Non-Browser Process to Port 443](./rules/windows/network_connection/susp_nonbrowser_https.yml) | T1071.001 | Medium |
| 15 | [File Modified in Suspicious Locations](./rules/windows/file_event/susp_file_write_locations.yml) | T1105 | Medium |

## Detection Engineering Methodology

Every rule in this pack follows a consistent workflow:

```
1. TTP Research → 2. Rule Writing → 3. Test with Atomic Red Team → 4. Tune FP → 5. Document
```

### Example: Suspicious PowerShell Detection

**TTP Research:** Adversaries commonly use `powershell -enc <base64>` to execute payloads without writing to disk. APT29, FIN7, and ransomware groups all use this technique.

**Rule Logic:** Detect `powershell.exe` or `pwsh.exe` processes with `-enc`, `-encodedcommand`, or `-e` flags in the command line. Exclude known administrative scripts.

**Testing:** Executed `Invoke-AtomicTest T1059.001` to validate detection in Wazuh/ELK.

**FP Tuning:** Added exceptions for common admin tools (PDQ, SCCM, Ansible) to reduce noise.

**Result:** Detects 100% of encoded PowerShell executions from Atomic Red Team with <5% false positive rate in a simulated enterprise environment.

## Tech Stack Used

| Tool | How I Used It |
|------|---------------|
| **Sigma CLI** | Rule validation and conversion to SIEM formats (Splunk, Elastic, Wazuh) |
| **Wazuh** | Ingested rules and triggered alerts from endpoint telemetry |
| **ELK Stack** | Visualized alert patterns, tuned rule logic |
| **Atomic Red Team** | Executed 20+ attack techniques to validate rule coverage |
| **Sysmon** | Provided process creation, network, and file event telemetry |

## Getting Started

### 1. Clone the rules
```bash
git clone https://github.com/rudraksh-dixit/sigma-soc-rules.git
cd sigma-soc-rules
```

### 2. Validate with Sigma CLI
```bash
pip install sigmatools
sigma check rules/  # Validate all rules
sigma convert -t splunk -p default rules/windows/process_creation/susp_encoded_powershell.yml
```

### 3. Deploy to your SIEM
- **Wazuh:** Copy rules to `/var/ossec/etc/rules/`
- **Splunk:** Use the converted SPL queries
- **ELK:** Use the converted Elasticsearch queries

### 4. Test with Atomic Red Team
```powershell
Import-Module "C:\AtomicRedTeam\AtomicRedTeam.psd1"
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

## Validation Results

All rules tested against Atomic Red Team techniques in a simulated AD environment with:
- 3 Windows endpoints (Workstation, Server, DC)
- Sysmon + Wazuh agent on each endpoint
- ELK Stack for log aggregation
- Clean traffic baseline for FP tuning

See [tests/validation-results.md](./tests/validation-results.md) for detailed results.

## Why This Project Matters

Most security students list "Sigma rules" as a skill. This repo proves I can:
- Write rules that actually detect real techniques, not just template rules
- Test and tune rules with real adversary simulations
- Handle false positives like a real SOC analyst
- Document the full detection engineering workflow

This is what a SOC analyst does. This repo is the proof.

## Connect

- GitHub: [github.com/rudraksh-dixit](https://github.com/rudraksh-dixit)
- LinkedIn: [linkedin.com/in/rudraksh-dixit](https://linkedin.com/in/rudraksh-dixit)
- APT Hunter AI: [github.com/rudraksh-dixit/apt-hunter-ai](https://github.com/rudraksh-dixit/apt-hunter-ai)
