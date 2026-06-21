# Sigma SOC Rules — Test Results

## Environment

- 3 Windows endpoints: Workstation (WIN10-1), File Server (SRV-APP), Domain Controller (DC-AD)
- Sysmon + Wazuh agent on all endpoints
- ELK Stack for log aggregation
- 7 days of clean traffic baseline for FP analysis
- Atomic Red Team for adversary simulation

## Validation Results

| # | Rule | Technique | Atomic Test | Detected | FP Rate | Notes |
|---|------|-----------|-------------|----------|---------|-------|
| 1 | Suspicious PowerShell - Encoded Command | T1059.001 | PowerShell Encoded Command | ✅ Yes | <5% | Detected all 3 test variants |
| 2 | LSASS Access via Procdump | T1003.001 | LSASS Memory Dumping | ✅ Yes | <1% | No FPs during baseline |
| 3 | Certutil Download | T1105 | Certutil Download | ✅ Yes | <2% | One FP from IT patch script - added filter |
| 4 | Scheduled Task Persistence | T1053.005 | Scheduled Task Creation | ✅ Yes | <8% | Some FPs from software installers |
| 5 | Registry Run Key Modification | T1547.001 | Registry Run Key | ✅ Yes | <5% | OneDrive FPs filtered |
| 6 | WMI Lateral Movement | T1047 | WMI Remote Execution | ✅ Yes | <3% | SCCM FPs identified |
| 7 | PsExec Service Creation | T1021.006 | PsExec Execution | ✅ Yes | <2% | Clean baseline detection |
| 8 | BITSAdmin Download | T1197 | BITSAdmin Download | ✅ Yes | <4% | Windows Update noise filtered |
| 9 | MSHTA Suspicious Execution | T1218.005 | MSHTA Execution | ✅ Yes | <1% | Rarely seen in clean traffic |
| 10 | Rundll32 Suspicious Invocation | T1218.011 | Rundll32 Execution | ✅ Yes | <6% | Some Windows internal FPs |
| 11 | Net User Discovery | T1087.001 | Net User Enumeration | ✅ Yes | <10% | Most FPs from admin scripts |
| 12 | Suspicious Service Installation | T1543.003 | Service Creation | ✅ Yes | <5% | Software install FPs |
| 13 | DNS Query to Suspicious TLD | T1071.001 | DNS Query | ✅ Yes | <12% | Higher FP - needs tuning per org |
| 14 | Non-Browser Process to Port 443 | T1071.001 | HTTPS Connection | ✅ Yes | <15% | Moderate FP - app updates |
| 15 | File Modified in Suspicious Locations | T1105 | File Drop | ✅ Yes | <8% | Temp file writes from legit processes |

## Summary

- **Detection Rate:** 15/15 (100%) for simulated Atomic Red Team tests
- **Average FP Rate:** ~5.5% in baseline enterprise traffic
- **Critical/High Severity Rules:** 10/15 were high or critical with <5% FP rate
- **Low/Medium Severity Rules:** 5/15 with moderate FP rates suitable for correlation use

## Tuning Notes

1. **Rule 11 (Net User Discovery):** High FP rate from admin scripts. Best used in correlation with other signals (e.g., followed by lateral movement).
2. **Rule 13 (DNS Suspicious TLD):** High FP due to legitimate marketing sites. Best combined with threat intel feeds.
3. **Rule 14 (Non-Browser HTTPS):** Moderate FP from app updates. Whitelist known updaters per environment.
4. **Rule 4 (Scheduled Tasks):** Add environment-specific software whitelists to reduce noise.

## Commands Used

```powershell
# List available techniques
Invoke-AtomicTest All -ShowDetails

# Execute specific test
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Execute technique on remote host
Invoke-AtomicTest T1047 -ComputerName SRV-APP -Credential $cred
```
