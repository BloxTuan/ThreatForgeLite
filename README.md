# ThreatForgeLite

ThreatForgeLite is a open-source lightweight Windows security analysis tool designed to perform quick scans for suspicious system activity and potential threat indicators.

The tool analyzes common persistence locations used by malware such as registry autoruns, startup programs, scheduled tasks, running processes, and network connections. It then generates a threat score and scan logs to help users understand the overall security state of their system.

## Features

- Windows Defender status check
- Running process analysis
- Registry autorun persistence scanning
- Startup folder inspection
- Scheduled task inspection
- PowerShell persistence detection
- Network connection analysis
- System error log review
- Threat score calculation
- Simple graphical interface
- Local scan logging

## How It Works

ThreatForgeLite performs a series of security checks on important parts of the Windows operating system that malware commonly abuses for persistence or remote control.

Each detection module contributes to a **Threat Score**, which helps determine the overall risk level of the system.

Threat levels:

- **LOW** – Minimal suspicious activity detected
- **MEDIUM** – Some suspicious indicators present
- **HIGH** – Multiple risk indicators detected

## Logs

Scan logs are stored locally at:
C:\ProgramData\ThreatScope\ThreatScope.log


These logs contain details about scan results and detected indicators.

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or newer
- Administrator privileges recommended

## Usage

1. Run the PowerShell script.
2. Click **Start Threat Scan**.
3. Wait for the scan to complete.
4. Review the generated threat score and logs.

## Disclaimer

ThreatForgeLite is a **basic threat detection tool** designed for educational and diagnostic purposes. It is not a replacement for a full antivirus or endpoint security solution.

## License

This project is licensed under the **MIT License**.

## Credits

Created by **shadownight4000**

Powered by **BloxTuan**

Check [ThreatForge](https://github.com/BloxTuan/ThreatForge) out which has advanced scanning and better scan rate.
