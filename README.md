# 🔍 Multi-Threaded Port Scanner

A network port scanner with multi-threading and service detection. Built for cybersecurity learning.

## Features
- Multi-threaded scanning (100x faster than sequential)
- Service detection for 30+ common services  
- Banner grabbing capability
- Export to JSON/CSV

## Quick Start
```bash
# Scan common ports
python3 portscanner.py -t 192.168.1.1

# Scan specific ports with banner grabbing
python3 portscanner.py -t scanme.nmap.org -p 22,80,443 -b -v

# Export results
python3 portscanner.py -t target.com -p 1-1000 -o results.json
```

## Options
- `-t` Target IPs/hostnames (comma-separated)
- `-p` Ports (e.g., `80,443,8000-9000`)
- `-T` Threads (default: 100)
- `-b` Grab banners
- `-v` Verbose
- `-o` Output file (.json/.csv)

## Tech Stack
Python 3.7+ | Threading | Sockets | Queue

## What I Learned
- Multi-threading with Queues and Locks
- TCP/IP socket programming
- Service detection techniques
- Thread synchronization

## Legal
For educational use and authorized testing only. Always get permission before scanning.

---
**Abdul Bari Mulla** | Aspiring Cybersecurity Professional
