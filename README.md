# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/KChinwe97/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
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

Searched the DeviceFileEvents for any device that had the word “tor” in it and discovered what looks like the user “abibiman” downloaded a Tor explorer. Did something that resulted in many tor-related files being created and copied to the desktop. There was also a file called “tor-shopping-list.txt” (2025-06-09T01:41:19.3771349Z) created on the Desktop. These events began at: 2025-06-09T01:38:16.7867082Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "chinwe-th-s2"
| where InitiatingProcessAccountName contains "abibi"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-06-09T01:38:16.7867082Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine containing the string “tor-browser-windows-x86_64-portable-14.5.3.exe” Based on the logs returned on 2025-06-09T01:38:02.7703557Z, an employee on the “chinwe-th-s2” device ran the file listed above silently “/S”
**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "chinwe-th-s2"
| where ProcessCommandLine contains "tor-browser"
| project Timestamp, DeviceName, ActionType, SHA256, FileName, FolderPath, AccountName, ProcessCommandLine
| take 10
```

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any evidence that the user actually opened the Tor browser. It was shown during investigation that the user did during this time 2025-06-09T01:28:45.5379214Z. There were several other instances of firefox.exe (Tor) as well as tor.exe was triggered afterwards.
**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "chinwe-th-s2"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, ActionType, SHA256, FileName, FolderPath, AccountName, ProcessCommandLine
| order by Timestamp desc
```

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication of the user using the Tor browser to connect to any of the known ports. On June 8, 2025, at 9:29:36 PM, the computer named chinwe-th-s2, under the user account abibiman, successfully established a network connection from local IP 10.0.0.162 to the remote IP address 94.23.68.187 on port 9001. The connection was initiated by the process tor.exe, which is part of the Tor Browser. There were a few other connections,
**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "chinwe-th-s2"
| where InitiatingProcessFileName contains "tor"
| project Timestamp, DeviceName, ActionType, RemoteIP, LocalIP, InitiatingProcessFileName, InitiatingProcessAccountName, RemotePort
| where RemotePort in ("9001")
| take 15
```

---

## 🕒 Chronological Event Timeline

### 1. 🚀 Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T21:38:02Z`
- **Event:** The user **"abibiman"** executed the TOR installer in silent mode.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.3.exe /S`
- **File Path:** `C:\Users\abibiman\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`
- **SHA256:** `3b7e78a4ccc935cfe71a0e4d41cc297d48a44e722b4a46f73b5562aed9c1d2ea`

---

### 2. 📂 File Creation - TOR Installation Files

- **Timestamp:** `2024-11-08T21:38:16Z–21:38:17Z`
- **Event:** TOR-related files created during install (`tor.exe`, `tor.txt`, etc.)
- **Action:** File creation from silent install detected.
- **Example File:** `tor.exe`
- **File Path:** `C:\Users\abibiman\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
- **SHA256:** `fe6d44cb69780e09c3a39f499e0e668bff9aa54b6cd9f363b753d59af713bea0`
- **Initiating Process:** `tor-browser-windows-x86_64-portable-14.5.3.exe /S`

---

### 3. 🧷 File Creation - Desktop Shortcut

- **Timestamp:** `2024-11-08T21:38:24Z`
- **Event:** Desktop shortcut `Tor Browser.lnk` created.
- **Action:** File creation detected.
- **File Path:** `C:\Users\abibiman\Desktop\Tor Browser\Tor Browser.lnk`
- **SHA256:** `f92eef1da4b14cebf252bf0644a1e427e4f73101f714eebd13d4454f42aa190e`
- **Initiating Process:** `tor-browser-windows-x86_64-portable-14.5.3.exe /S`

---

### 4. 🔄 Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T21:28:45Z`
- **Event:** `firefox.exe` (TOR browser component) executed.
- **Action:** TOR browser startup detected.
- **File Path:** `C:\Users\abibiman\Desktop\Tor Browser\Browser\firefox.exe`
- **SHA256:** `8c7dbbc89d77775b0e041b9f2050105767628e97398071ac61025759899db86b`

---

### 5. ⚙️ Additional TOR Browser Processes

- **Timestamps:**
  - `21:28:52Z`: Firefox GPU rendering started.
  - `21:28:55Z`: `tor.exe` process initiated.
  - `21:28:55Z–21:28:57Z`: Multiple Firefox content processes created.
  - `21:29:41Z–21:35:53Z`: Additional Firefox tabs opened.
  - `21:38:33Z–21:38:39Z`: Firefox GPU and utility processes launched.
- **Examples:**
  - `"firefox.exe" -contentproc --channel=2228 ... gpu`
  - `"tor.exe" -f "C:\Users\abibiman\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\torrc" ...`

---

### 6. 🌐 Network Connection - TOR Network

- **Timestamps & Endpoints:**
  - `2024-11-08T21:29:36Z`: `tor.exe` → `94.23.68.187:9001`
  - `2024-11-08T21:29:39Z`: `tor.exe` → `89.58.12.210:9001`
  - `2024-11-08T21:38:46Z`: Reconnected to both above IPs.
- **Action:** TOR network activity confirmed.
- **Process:** `tor.exe`
- **Local IP:** `10.0.0.162`

---

### 7. 📝 File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T21:41:19Z`
- **Event:** `tor-shopping-list.txt` created on desktop.
- **Action:** File creation detected.
- **File Path:** `C:\Users\abibiman\Desktop\tor- shopping-list.txt`
- **SHA256:** `0b4eb8fc10a3caa261bb3e7324c1c88017e2cedfdb5e1fdce12d3ccf435dbcfb`
- **Initiating Process:** `notepad.exe`

---

## Summary

The user abibiman on the device chinwe-th-s2 engaged in activities related to the Tor Browser on June 8, 2025, between 9:28:45 PM and 9:41:19 PM. The sequence of events began with the execution of firefox.exe, indicating the start of the Tor Browser. Shortly after, the tor.exe process was initiated, establishing network connections to remote IPs 94.23.68.187 and 89.58.12.210 on port 9001, confirming Tor network activity. The Tor Browser installer tor-browser-windows-x86_64-portable-14.5.3.exe was executed silently, resulting in the creation of several Tor-related files, including tor.exe, license files, and a desktop shortcut. Multiple firefox.exe processes were created, primarily for browser tabs and graphics rendering, indicating active use of the Tor Browser. Additionally, a file named tor- shopping-list.txt and its shortcut were created, suggesting user activity possibly related to Tor usage, though the purpose remains unclear. The consistent use of the Tor Browser and its network connections suggests deliberate engagement with the Tor network, potentially for anonymized browsing.---

## Response Taken

TOR usage was confirmed on the endpoint `chinwe-th-s2` by the user `abibiman`. The device was isolated, and the user's direct manager was notified.

---
