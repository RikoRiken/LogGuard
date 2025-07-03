# LogGuard v1.0 - Linux Authentication Log Analyzer

import os
import argparse
import re

def show_banner():
    print(r"""
          
     ██▓    ▒█████   ▄████      ▄████ █    ██ ▄▄▄      ██▀███ ▓█████▄ 
    ▓██▒   ▒██▒  ██▒██▒ ▀█▒    ██▒ ▀█▒██  ▓██▒████▄   ▓██ ▒ ██▒██▀ ██▌
    ▒██░   ▒██░  ██▒██░▄▄▄░   ▒██░▄▄▄▓██  ▒██▒██  ▀█▄ ▓██ ░▄█ ░██   █▌
    ▒██░   ▒██   ██░▓█  ██▓   ░▓█  ██▓▓█  ░██░██▄▄▄▄██▒██▀▀█▄ ░▓█▄   ▌
    ░██████░ ████▓▒░▒▓███▀▒   ░▒▓███▀▒▒█████▓ ▓█   ▓██░██▓ ▒██░▒████▓ 
    ░ ▒░▓  ░ ▒░▒░▒░ ░▒   ▒     ░▒   ▒░▒▓▒ ▒ ▒ ▒▒   ▓▒█░ ▒▓ ░▒▓░▒▒▓  ▒ 
    ░ ░ ▒  ░ ░ ▒ ▒░  ░   ░      ░   ░░░▒░ ░ ░  ▒   ▒▒ ░ ░▒ ░ ▒░░ ▒  ▒ 
    ░ ░  ░ ░ ░ ▒ ░ ░   ░    ░ ░   ░ ░░░ ░ ░  ░   ▒    ░░   ░ ░ ░  ░ 
        ░  ░   ░ ░       ░          ░   ░          ░  ░  ░       ░ 
                                                                
                LogGuard v1.0 - Linux Authentication Log Analyzer
          
        """)
    
def find_log_files():
    possible_paths = [
        "/var/log/auth.log", # Debian/Ubuntu authentication log
        "/var/log/secure",   # Red Hat/CentOS authentication log
    ]

    for path in possible_paths:
        if os.path.isfile(path):
            print (f"ℹ️  Log file detected: {path}\n")
            return path

    print("❌ No standard authentication log files found.\n")
    print("💡 Tip: Use --custom-log to specify one.\n")
    return None

def parse_arguments():
    parser = argparse.ArgumentParser(description="LogGuard - Linux Authentication Log Analyzer")
    parser.add_argument("--custom-log", 
                        metavar="[PATH_TO_LOG]",
                        type=str, 
                        help="Path to a custom log file to analyze")
    parser.add_argument("--export-txt",
                        metavar="[FILE_NAME].txt",
                        type=str,
                        help="Export results to a text file with the specified name"
                        )
    return parser.parse_args()

def extract_ssh_failures(log_path):
    ssh_failures_pattern = re.compile( 
                r'(?P<date>\w{3} +\d{1,2} +\d{2}:\d{2}:\d{2}) .*sshd.*Failed password for( invalid user)? (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )

    failed_logins = []

    with open(log_path, 'r') as file:
        for line in file:
            match = ssh_failures_pattern.search(line)
            if match:
                date = match.group('date')
                user = match.group('user')
                ip = match.group('ip')
                failed_logins.append((date, user, ip))

    if not failed_logins:
        print("✅ No failed SSH authentication found.")
        return
    
    else:
        print(f"🚨 Detected {len(failed_logins)} failed SSH login attempts:\n")
        for entry in failed_logins:
            print(f"[{entry[0]}] Failed login for user '{entry[1]}' from {entry[2]}")

    return failed_logins

def extract_ssh_successes(log_path):
    ssh_successes_pattern = re.compile(
                r'(?P<date>\w{3} +\d{1,2} +\d{2}:\d{2}:\d{2}) .*sshd.*Accepted password for( invalid user)? (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )

    successful_logins = []

    with open(log_path, 'r') as file:
        for line in file:
            match = ssh_successes_pattern.search(line)
            if match:
                date = match.group('date')
                user = match.group('user')
                ip = match.group('ip')
                successful_logins.append((date, user, ip))

    if not successful_logins:
        print("✅ No successful SSH authentication found.")
        return

    else:
        print(f"\n🔑 Detected {len(successful_logins)} successful SSH login attempts:\n")
        for entry in successful_logins:
            print(f"[{entry[0]}] Successful login for user '{entry[1]}' from {entry[2]}")

    return successful_logins

def analyse_privilege_escalation(log_path):
    sudo_pattern = re.compile(
                r'(?P<date>\w{3} +\d{1,2} +\d{2}:\d{2}:\d{2}) .*sudo:.*?(?P<user>\w+).*COMMAND=(?P<cmd>.+)'
    )

    su_pattern = re.compile(
                r'(?P<date>\w{3} +\d{1,2} +\d{2}:\d{2}:\d{2}) .*su:.*? for user (?P<target>\w+) by (?P<user>\w+)'
    )

    privilege_escalation_attempts = []

    with open(log_path, 'r') as file:
        for line in file:
            sudo_match = sudo_pattern.search(line)
            if sudo_match:
                date = sudo_match.group('date')
                user = sudo_match.group('user')
                cmd = sudo_match.group('cmd')
                privilege_escalation_attempts.append(("sudo", date, user, cmd))

            su_match = su_pattern.search(line)
            if su_match:
                date = su_match.group('date')
                status = "Successful" if "session opened" in line else "Failed"
                target = su_match.group('target')
                user = su_match.group('user')
                privilege_escalation_attempts.append(("su", date, status, target, user))

    if not privilege_escalation_attempts:
        print("\n✅ No privilege escalation (su, sudo) attempts found.")
        return

    print(f"\n⛔️ Detected {len(privilege_escalation_attempts)} privilege escalation attempts:\n")
    
    for entry in privilege_escalation_attempts:
        if entry[0] == "sudo":
            print(f"[{entry[1]}] Sudo command executed by '{entry[2]}': {entry[3]}")
        elif entry[0] == "su":
            print(f"[{entry[1]}] {entry[2]} su for '{entry[3]}' by '{entry[4]}'")

    return privilege_escalation_attempts

def export_results_txt(export_txt, failed_logins, successful_logins, privilege_escalation_attempts):
    with open(export_txt, 'w') as file:
        file.write("Failed SSH Logins:\n")
        for entry in failed_logins:
            file.write(f"[{entry[0]}] Failed login for user '{entry[1]}' from {entry[2]}\n")

        file.write("\nSuccessful SSH Logins:\n")
        for entry in successful_logins:
            file.write(f"[{entry[0]}] Successful login for user '{entry[1]}' from {entry[2]}\n")

        file.write("\nPrivilege Escalation Attempts:\n")
        for entry in privilege_escalation_attempts:
            if entry[0] == "sudo":
                file.write(f"[{entry[1]}] Sudo command executed by '{entry[2]}': {entry[3]}\n")
            elif entry[0] == "su":
                file.write(f"[{entry[1]}] {entry[2]} su for '{entry[3]}' by '{entry[4]}'\n")

def main():
    args = parse_arguments()

    if args.custom_log:
        if os.path.isfile(args.custom_log):   
            log_path = args.custom_log

        else: 
            print(f"❌ Error: Custom log file '{args.custom_log}' does not exist.\n")
            return
        
    else:
        log_path = find_log_files()  

    if not log_path:
        print("Impossible to find log to analyze, aborting the mission...\n")
        return
    
    print(f"📂 Analyzing log file: {log_path}\n")

    failed_logins = extract_ssh_failures(log_path)

    successful_logins = extract_ssh_successes(log_path)

    privilege_escalation_attempts = analyse_privilege_escalation(log_path)

    print("\n🔍 Analysis complete. Review the output for any suspicious activity.\n")

    if args.export_txt:
        print(f"✅ Exporting results to '{args.export_txt}'...\n")

        export_results_txt(args.export_txt, failed_logins, successful_logins, privilege_escalation_attempts)

if __name__ == "__main__":
    show_banner()
    main()

# TODO: Add export to json?
# TODO: Summarize statistics with web interface?