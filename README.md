

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/MichaelKirbyIT/ThreatHuntingScenarioTor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "michaellabuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-05-11T18:08:10.4067883Z`. These events began at `2026-05-11T17:32:51.340943Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "michael-mde-vm"  
| where InitiatingProcessAccountName == "michaellabuser"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2026-05-11T17:32:51.340943Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1184" height="521" alt="image" src="https://github.com/user-attachments/assets/bf7d074e-e8b0-467c-a0b7-e4d8387ae68e" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.13.exe". Based on the logs returned, at `2026-05-11T17:36:17.0097036Z`, an employee on the "michael-mde-vm" device ran the file `tor-browser-windows-x86_64-portable-15.0.13.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "michael-mde-vm"
| where ProcessCommandLine startswith "tor-browser-windows-x86_64-portable-15.0.13.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1420" height="187" alt="image" src="https://github.com/user-attachments/assets/eecf61bb-d871-44be-8758-24364c915d27" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "michaellabuser" actually opened the TOR browser. There was evidence that they did open it at `2026-05-11T17:37:05.2927851Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "michael-mde-vm"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1416" height="453" alt="image" src="https://github.com/user-attachments/assets/fd77d26b-1808-48e6-9b2f-cda0168f20c6" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-05-11T17:37:43.8157986Z`, an employee on the "michael-mde-vm" device successfully established a connection to the remote IP address `217.160.98.239` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\michaellabuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There was another connection to a site over port `9150`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "michael-mde-vm"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1738" height="294" alt="image" src="https://github.com/user-attachments/assets/29373080-f21a-47af-a244-93256f6e18c4" />

---

### 5. Searched the `DeviceFileEvents` Table any files related to TOR.

Searched for any indication that the user "michaellabuser" created or modified any files related to TOR. At `2026-05-11T18:08:10.4067883Z`, the user created a file named `tor-shopping-list.txt`, located in the folder `C:\Users\michaellabuser\Desktop\tor-shopping-list.txt`.


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "michael-mde-vm"
| where InitiatingProcessAccountName == "michaellabuser"
| where Timestamp >= datetime(2026-05-11T17:32:51.340943Z)
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName, InitiatingProcessFileName
```
<img width="1415" height="415" alt="image" src="https://github.com/user-attachments/assets/185f023b-a418-4145-a629-315a4696b1b4" />



---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-05-11T17:32:51.340943Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.13.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\michaellabuser\Downloads\tor-browser-windows-x86_64-portable-15.0.13.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-05-11T17:36:17.0097036Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-15.0.13.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.13.exe  /S`
- **File Path:** `C:\Users\michaellabuser\Downloads\tor-browser-windows-x86_64-portable-15.0.13.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-05-11T17:37:05.2927851Z`
- **Event:** User "michaellabuser" on the virtual machine "michael-mde-vm" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\michaellabuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-05-11T17:37:43.8157986Z`
- **Event:** A network connection to IP `217.160.98.239` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\michaellabuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-05-11T17:37:34.9948365Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "michaellabuser" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-05-11T18:08:10.4067883Z`
- **Event:** The user "michaellabuser" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\michaellabuser\Desktop\tor-shopping-list.txt`



---

## Summary

Analysis of endpoint activity on `michael-mde-vm` reveals that the user `michaellabuser` successfully downloaded, installed, and utilized the Tor Browser to bypass standard network security controls. Following the establishment of a connection to the Tor relay network, evidence suggests the user engaged in browsing activities and created a "shopping list" document on the desktop.

## Evidence

- [Tor Download](https://github.com/MichaelKirbyIT/ThreatHuntingScenarioTor/blob/main/Evidence-Tor-Download)
- [Tor Install](https://github.com/MichaelKirbyIT/ThreatHuntingScenarioTor/blob/main/Evidence-Tor-Install)
- [Tor Process Creation](https://github.com/MichaelKirbyIT/ThreatHuntingScenarioTor/blob/main/Evidence-Tor-Process-Creation)
- [Tor Usage](https://github.com/MichaelKirbyIT/ThreatHuntingScenarioTor/blob/main/Evidence-Tor-Usage)
- [Tor File Creation](https://github.com/MichaelKirbyIT/ThreatHuntingScenarioTor/blob/main/Evidence-Tor-File-Creation)


---

## Response Taken

### 1. Immediate Containment
- Host Isolation: At 13:15 UTC, the host michael-mde-vm was isolated via Microsoft Defender for Endpoint (MDE). This severed all active network connections to the Tor relay network while maintaining a secure management channel for forensic triage.

- Process Termination: Utilizing MDE’s remote shell capabilities, all running instances of tor.exe and firefox.exe (Tor Browser) were force-terminated to collapse the anonymized tunnel.

- Identity Lockdown: Initiated a temporary account disablement for michaellabuser in Entra ID to mitigate the risk of lateral movement or unauthorized access to cloud resources.

### 2. Eradication & Forensic Collection
- Artifact Preservation: A comprehensive "Investigation Package" was pulled from the endpoint, including a memory dump and a copy of the tor-shopping-list.txt file to serve as evidence of intent.

- Secure Deletion: The unauthorized \Desktop\Tor Browser\ directory and the installer located in the Downloads folder were purged using a secure wipe protocol to ensure no persistence remained.

- Registry Sanitation: Scanned and removed specific user-level registry keys located in HKEY_CURRENT_USER\Software created during the silent installation.

### 3. Recovery & Verification
- Credential Rotation: Triggered a mandatory password reset for the user and revoked all active MFA session tokens to ensure the identity was fully re-secured.

- Endpoint Scouring: Performed a full disk scan for other unauthorized portable executables or "Living off the Land" (LotL) tools; the scan returned clean.

- System Re-Integration: Host isolation was successfully lifted at 15:00 UTC after verifying that all outbound communication to known Tor relay IPs had ceased.

### 4. Stakeholder Communication
- Executive Reporting: A finalized incident summary was delivered to the IT Security Manager detailing the timeline and the discovered "shopping list" artifact.

- Managerial Follow-up: The user’s department head was notified to schedule a Security Awareness Interview to address the policy violation and assess the user's motive for seeking illicit services.

---
