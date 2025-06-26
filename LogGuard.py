import os
import argparse

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
            print (f"Log file detected: {path}")
            return path

    print("❌ No standard authentication log files found.")
    print("💡 Tip: Use --custom-log to specify one.")
    return None

def parse_arguments():
    parser = argparse.ArgumentParser(description="LogGuard - Linux Authentication Log Analyzer")
    parser.add_argument("--custom-log", 
                        metavar="",
                        type=str, 
                        help="Path to a custom log file to analyze")
    return parser.parse_args()

def main():
    args = parse_arguments()

    if args.custom_log:
        if os.path.isfile(args.custom_log):   
            log_path = args.custom_log

        else: 
            print(f"❌ Error: Custom log file '{args.custom_log}' does not exist.")
            return
        
    else:
        log_path = find_log_files()  

    if not log_path:
        print("Impossible to find log to analyze, aborting the mission...")
        return
    
    print(f"📂 Analyzing log file: {log_path}")

if __name__ == "__main__":
    show_banner()
    main()


# TODO: Add SSH analysis
# TODO: Add sudo/su activity detection
# TODO: Summarize statistics