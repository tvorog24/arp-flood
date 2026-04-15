# arp-flood
ARP Reply Flooding Tool for Windows x64

## Description
arp-flood allows to send specified number of randomly composed ARP Reply packets from a selected interface
## Requirements
- Windows x64 (run as Administrator)
- `gcc.exe`, `make.exe` (available via [MSYS2 UCRT64](https://www.msys2.org))
- [Git for Windows](https://git-scm.com/install/windows)
- [Npcap SDK](https://npcap.com/#download) 

## Installation
### Clone the repository
```git clone https://github.com/tvorog24/arp-flood.git```
### Install dependencies
Download and install Npcap SDK to `C:\npcap-sdk`

## Building
> **Important:**
> `gcc.exe` and `make.exe` must be included in your `PATH`
```powershell 
PS> make
```
## Cleaning
```powershell
PS> make clean
```
## Running
> **Important:**
> Run PowerShell as Administator

```powershell 
PS> .\arp_flood.exe
```
