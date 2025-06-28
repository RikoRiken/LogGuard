<h1 align="center">
    <img src="./assets/LogGuard-logo.png">
</h1>

<p align="center">
LogGuard is a lightweight, beginner-friendly, and extensible Python tool designed to analyze and monitor Linux authentication logs.  
Its primary goal is to help identify suspicious login attempts, unauthorized access, and privilege escalation.
</p>

<p align="center">
  <a href="#description">Description</a> •
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage--demonstration">Usage & Demonstration</a>
</p>

<br>

## Description

**LogGuard** is a lightweight, modular, and beginner-friendly Python tool designed to analyze Linux system authentication logs.

Its goal is to help identify suspicious login activity — such as failed SSH attempts, unauthorized access, and privilege escalation commands (e.g., `sudo`, `su`) — by parsing real system logs (`/var/log/auth.log`, `/var/log/secure`, or custom files).

Originally created as a learning project to explore Python and system log parsing, LogGuard now serves as a solid base for anyone who wants to:
- Understand how authentication events are logged on Linux
- Build simple tools for threat detection or audit purposes
- Practice Python coding in a real-world context

The code is clean and modular, making it easy to extend or integrate into larger security tools.
<br>

## Features

<br>

## Installation

1. **Clone the repository**:

```bash
git clone https://github.com/RikoRiken/LogGuard.git
cd LogGuard
```
<br>

2. **Run the tool**:
```bash
python3 LogGuard.py


💡 You can also specify a custom log file:

python3 LogGuard.py --custom-log path/to/custom_file.log
```
<br>

3. *(Optionnal)* **Create a virtual environment**:
```bash
python3 -m venv venv
source /venv/bin/active
```
<br>

## Usage & Demonstration