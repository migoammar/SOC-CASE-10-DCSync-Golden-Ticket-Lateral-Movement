# SOC-CASE-10: DCSync → Golden Ticket → Lateral Movement (Active Directory)

## Objective
Investigate a full Active Directory attack chain — DCSync, Golden Ticket forgery, and Lateral Movement — carried out against a real AD lab (Domain Controller + domain-joined client), tracing the attack across two hosts and identifying which stages left evidence and which did not.

## Environment
- Domain Controller: DC01 / WIN-CSPQTSQK31T.corp.local (Windows Server 2022, 10.0.2.15), domain corp.local (NetBIOS: CORP)
- Client: Windows 10 Lab / DESKTOP-R0Q45UL (10.0.2.20), domain-joined, reused from Cases 07-09
- Domain user: mirgani (elevated to Domain Admin for this test)
- Tool used by the attacker: mimikatz
- Logging: Sysmon + Windows Security auditing on both hosts, forwarded via Splunk Universal Forwarder to a Splunk Indexer (port 9997) running on Windows 10 Lab

## Hypothesis

**Stage 1 — DCSync**
- IF: attacker performed a DCSync attack against the krbtgt account, evidenced by EventCode=4662 with GUID 1: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 and GUID 2: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2, Account Name=Administrator
- THEN: obtaining the krbtgt hash allows the attacker to make a completely forged Kerberos ticket (Golden Ticket) using mimikatz
- SO: `index=main host=WIN-CSPQTSQK31T* EventCode=4662 "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" OR "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" earliest="09/03/2026:00:04:00" latest="09/03/2026:00:05:30"`

**Stage 2 — Golden Ticket**
- IF: klist output shows a forged Kerberos TGT (Golden Ticket) for Client=Administrator@corp.local with an abnormal End Time=8/31/2036
- THEN: this gives the attacker long-term persistent access as Administrator, because the forged ticket is not tied to any real password and remains valid even if the Administrator account's password is later changed
- SO: `index=main host=DESKTOP-R0Q45UL* OR host=WIN-CSPQTSQK31T* earliest="09/03/2026:00:00:00" latest="09/03/2026:00:20:00"`

**Stage 3 — Lateral Movement**
- IF: a successful SMB access to \\WIN-CSPQTSQK31T.corp.local\C$ was observed from host DESKTOP-R0Q45UL using the forged Administrator ticket, with no password authentication prompt
- THEN: this indicates the attacker used Pass-the-Ticket to move laterally to the Domain Controller with full Administrator access, without needing the real Administrator password
- SO: `index=main host=WIN-CSPQTSQK31T* (EventCode=4624 OR EventCode=5140) earliest="09/03/2026:00:04:00" latest="09/03/2026:00:20:00"`

## Investigation Timeline
1. Queried `index=main host=WIN-CSPQTSQK31T* EventCode=4662` → found 2 events at 12:04:49.295 AM matching GUIDs 1131f6aa and 1131f6ad, Account Name=Administrator → confirmed a DCSync replication request against the DC.
2. Checked `klist` on Windows 10 Lab → found an active TGT for Administrator@corp.local, Start Time 9/3/2026, End Time 8/31/2036 → confirmed a forged, long-lived Kerberos ticket with no corresponding Event Log entry for its creation.
3. Executed `dir \\WIN-CSPQTSQK31T.corp.local\C$` from Windows 10 Lab → access succeeded instantly with no credential prompt → confirmed the forged ticket was used to authenticate to the DC as Administrator.

## Attack Timeline
- 09/03/2026 12:04:49 AM — DCSync executed from Windows 10 Lab against DC01; krbtgt NTLM hash obtained.
- 09/03/2026 (same session) — Golden Ticket created via mimikatz `kerberos::golden`, injected via `/ptt`; forged TGT for Administrator@corp.local set to expire 8/31/2036.
- 09/03/2026 (same session) — Lateral Movement confirmed: `dir \\WIN-CSPQTSQK31T.corp.local\C$` succeeded using the forged ticket, no password required.

## MITRE Mapping
| Stage | Tactic | Technique ID | Technique Name |
|---|---|---|---|
| DCSync | Credential Access | T1003.006 | OS Credential Dumping: DCSync |
| Golden Ticket | Persistence / Privilege Escalation | T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket |
| Lateral Movement | Lateral Movement | T1550.003 | Use Alternate Authentication Material: Pass the Ticket |

## Findings
- The attacker (via account mirgani, granted Domain Admin) obtained the krbtgt account's NTLM hash from the Domain Controller using a DCSync replication request (EventCode 4662, GUIDs confirming Get-Changes and Get-Changes-All rights).
- Using the krbtgt hash, the attacker forged a Golden Ticket for the Administrator account (RID 500) with an abnormal 10-year validity period, not tied to any real password.
- The forged ticket was used to access the Domain Controller's C$ share with no authentication prompt, confirming full Lateral Movement with Domain Admin-level access.
- Credential theft combined with a persistent forged identity grants the attacker durable, password-reset-proof access to the entire domain.

## Evidence

**Stage 1 — DCSync**
Query: `index=main host=WIN-CSPQTSQK31T* EventCode=4662 "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" OR "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" earliest="09/03/2026:00:04:00" latest="09/03/2026:00:05:30"`
- Evidence 1: EventCode=4662, TaskCategory=Directory Service Access
- Evidence 2: Properties contains GUID {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes)
- Evidence 3: Properties contains GUID {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes-All)
- Evidence 4: Account Name=Administrator, Security ID=S-1-5-21-...-500
- Evidence 5: ComputerName=WIN-CSPQTSQK31T.corp.local
- Evidence 6: Timestamp=09/03/2026 12:04:49.295 AM

**Stage 2 — Golden Ticket**
Query: none (verified via local `klist`, not a log source)
- Evidence 7: Client=Administrator @ corp.local
- Evidence 8: Server=krbtgt/corp.local @ corp.local
- Evidence 9: Start Time=9/3/2026 9:15:23 AM
- Evidence 10: End Time=8/31/2036 9:15:23 AM (abnormal ~10-year lifetime)

**Stage 3 — Lateral Movement**
Query: `index=main host=WIN-CSPQTSQK31T* (EventCode=4624 OR EventCode=5140) earliest="09/03/2026:00:04:00" latest="09/03/2026:00:20:00"`
- Evidence 11: Successful SMB access to \\WIN-CSPQTSQK31T.corp.local\C$, no credential prompt
- Evidence 12: Access performed using the Administrator identity from the forged ticket

## Attacker Mindset
- The attacker used DCSync because it abuses a legitimate replication protocol, making it look like normal Domain Controller traffic.
- The attacker chose the Administrator account to get the highest privilege level in the whole domain.
- The attacker set the ticket lifetime to 10 years to keep access working even after a password reset.
- The attacker used a normal `dir` command over SMB to avoid triggering suspicion.

## False Positive Analysis
*(carried over as-is from prior review)*

## Detection Logic (Sigma)

**Rule 1 — DCSync**
```yaml
title: DCSync Replication Request Detected
id: 10a1e001-0001-4a1a-9c01-dcsync000001
status: experimental
description: Detects a DCSync-style directory replication request using Get-Changes and Get-Changes-All extended rights
date: 2026/09/03
author: MIRGANI AMMAR
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
  condition: selection
falsepositives:
  - Legitimate Domain Controllers performing normal AD replication
level: high
tags:
  - attack.credential_access
  - attack.t1003.006
```

**Rule 2 — Golden Ticket (anomaly-based)**
```yaml
title: Abnormally Long Kerberos Ticket Lifetime (Possible Golden Ticket)
id: 10a1e002-0002-4a1a-9c02-goldenticket02
status: experimental
description: Flags Kerberos TGTs with an unusually long validity period, indicating a possible forged Golden Ticket
date: 2026/09/03
author: MIRGANI AMMAR
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
  filter:
    TicketLifetime_hours: '>24'
  condition: selection and filter
falsepositives:
  - Custom domain policies with extended ticket lifetimes (rare)
level: high
tags:
  - attack.persistence
  - attack.t1558.001
```

**Rule 3 — Lateral Movement (Pass-the-Ticket usage)**
```yaml
title: SMB Access Using Forged Administrator Ticket
id: 10a1e003-0003-4a1a-9c03-lateralmove03
status: experimental
description: Detects SMB share access authenticated via a suspected forged Kerberos ticket
date: 2026/09/03
author: MIRGANI AMMAR
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5140
    AccountName: 'Administrator'
  condition: selection
falsepositives:
  - Legitimate administrative access using real Administrator credentials
level: medium
tags:
  - attack.lateral_movement
  - attack.t1550.003
```

## Cross-host Correlation
- DCSync happened on the DC, but the tool ran from Windows 10 Lab.
- The Golden Ticket was created on Windows 10 Lab only, with no log on the DC side.
- Lateral Movement went from Windows 10 Lab back to the DC.
- All three stages happened in the same time window using the same forged identity (Administrator), so they are one attack chain across two hosts.

## Detection Gaps
- Golden Ticket creation has no Event Log entry because it happens fully offline with mimikatz.
- The only way to catch it is by checking ticket lifetime, not by looking for a specific event.
- Normal SIEM rules on Event 4768/4769 alone will miss Golden Ticket usage.

## Recommendations
- Restrict which accounts have DS-Replication-Get-Changes-All rights.
- Alert on Event 4662 with the DCSync GUIDs.
- Monitor ticket lifetimes and alert on anything longer than the domain default (10 hours).
- Reset the krbtgt password twice after any suspected DCSync.

## Lessons Learned
- One compromised Domain Admin account can lead to full domain compromise using DCSync and a Golden Ticket.
- Some attack stages leave no direct log, so detection needs anomaly checks, not just Event Codes.

## Conclusion
The attacker used DCSync to steal the krbtgt hash, forged a Golden Ticket for Administrator, and used it to move laterally to the DC without a real password. This shows that Kerberos persistence can survive a password reset, so resetting krbtgt is the only real fix.

## References
- MITRE ATT&CK T1003.006 — https://attack.mitre.org/techniques/T1003/006/
- MITRE ATT&CK T1558.001 — https://attack.mitre.org/techniques/T1558/001/
- MITRE ATT&CK T1550.003 — https://attack.mitre.org/techniques/T1550/003/
