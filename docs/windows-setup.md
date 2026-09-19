# Windows Setup

## 1. Python

Install Python 3.10 or later and create a virtual environment:

```powershell
py -3.10 -m venv .venv
.venv\Scripts\python -m pip install --upgrade pip
.venv\Scripts\python -m pip install -r requirements.txt
```

## 2. Npcap

Install the current Npcap release for Windows. Allow the installer options needed for WinPcap-compatible applications if your lab setup requires them. Reboot if the installer requests it.

Packet Watch uses Scapy for capture and therefore needs Npcap available to Windows. The tool does not use Wireshark.

## 3. Privileges

Open PowerShell/Command Prompt as Administrator when required by the capture driver/interface permissions.

## 4. Interfaces

Run:

```powershell
.venv\Scripts\python -m packet_watch interfaces
```

Copy the interface name exactly into:

```powershell
.venv\Scripts\python -m packet_watch monitor --interface "INTERFACE NAME"
```

## 5. APIs

Copy `.env.example` to `.env` and set `PACKET_WATCH_ABUSEIPDB_API_KEY`. Do not commit `.env`.
