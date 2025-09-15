# PenForge: Advanced Penetration Testing Framework

## Overview
PenForge is a modular, Python-based penetration testing framework designed for advanced users preparing for Offensive Security certifications (e.g., OSCP+) and ethical hacking projects. It surpasses traditional tools like Metasploit by offering multi-port scanning, customizable plugins, and exploit chaining. Developed for lab environments (e.g., Metasploitable, VulnHub, Hack The Box), PenForge ensures compliance with ethical and legal standards. All testing must be conducted in authorized lab setups to adhere to OSCP+ rules and avoid legal issues.

### Key Features
- **Multi-Port Scanning**: Threaded scanning for efficient reconnaissance across multiple ports.
- **Modular Plugins**: Includes banner grabbing, buffer overflow testing, and brute-force attacks; extensible for custom needs.
- **Exploit Chaining**: Chain multiple exploits for complex attack scenarios on specific ports.
- **Robust Error Handling**: Timeouts, rate limiting, and logging for reliable testing.
- **Extensibility**: Add plugins or exploits for vulnerabilities like SQL injection or XSS.

## Installation
1. Ensure Python 3.8+ is installed.
2. Clone the repository:
   ```
   git clone https://github.com/malware1004/penforge.git
   cd penforge
   ```
3. No external dependencies required (uses standard Python libraries: socket, threading, etc.).

## Usage
Run the framework with:
```
python3 penforge_advanced.py --target <IP> --ports <comma-separated ports, e.g., 80,443,9999>
```
- **Example**: `python3 penforge_advanced.py --target 192.168.1.100 --ports 80,9999`
- Output: Scan results, plugin findings, and exploit outcomes.

For OSCP+ exam preparation:
- Test in a lab environment (e.g., Metasploitable).
- Document results with screenshots of `proof.txt` (via `cat`) and IP (via `ip addr`).
- Follow OSCP+ rules: Limit advanced tool use to one target machine.

## Plugins and Exploits
- **BannerGrabPlugin**: Retrieves service banners for reconnaissance.
- **BufferOverflowPlugin**: Tests for buffer overflow vulnerabilities with crafted payloads.
- **BruteForcePlugin**: Attempts credential brute-forcing with a customizable wordlist.
- **Custom Shell Exploit**: Delivers shellcode for reverse shell simulations (lab-only).

Extend by subclassing `PluginBase` or adding to `exploit_chains`.

## Code Structure
- `PenForgeAdvanced`: Core class for scanning, plugin execution, and exploit chaining.
- `PluginBase`: Base class for plugin development.
- Threaded architecture for performance.

## Ethical Considerations
- Use only in authorized lab environments.
- Unauthorized testing may violate laws (e.g., CFAA in the US).
- For OSCP+: Adhere to exam rules, document thoroughly, and limit to one target.
- Always obtain explicit permission for testing.

## Acknowledgments
Inspired by Metasploit and Nmap. Developed for educational purposes on September 15, 2025.
