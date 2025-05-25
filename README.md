# SSH Honeypot

A custom SSH honeypot written in Python using Paramiko to simulate a vulnerable SSH server for logging unauthorized access attempts and commands.

## Features
- Logs login attempts (username, password, IP)
- Emulates basic shell commands (`pwd`, `ls`, etc.)
- Analyzes top IPs, credentials, and commands

## Files
- `honeypot.py`: SSH honeypot server
- `analyze_honeypot.py`: Analysis script for logs
- `csv/`: CSV exports of logs
- `data/`: Visualizations

## Do NOT upload:
- `server_key`, `audits.log`, `cmd_audits.log`

## Run
```bash
python honeypot.py
