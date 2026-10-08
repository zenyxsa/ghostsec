#!/usr/bin/env python3
import socket
import os
import subprocess
import re
import argparse
import sys
import time
import threading
from datetime import datetime
import json
import platform
from ghostsec.osint import analyze_url, breach_lookup, print_url_report, print_breach_report

# Attempt to load colorama for hacker-style colored terminal output
try:
    import colorama
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("[!] Colorama not installed. Run 'pip install colorama' for colored output.")
    # Fallback to empty strings if colorama is missing
    class DummyColor:
        def __getattr__(self, name):
            return ""
    Fore = DummyColor()
    Style = DummyColor()

def print_banner():
    """Prints the Hacker-style ASCII art banner."""
    banner = fr"""{Fore.GREEN}{Style.BRIGHT}
   ____ _               _   ____           
  / ___| |__   ___  ___| |_|  _ \  ___ ___ 
 | |  _| '_ \ / _ \/ __| __| | | |/ _ / __|
 | |_| | | | | (_) \__ \ |_| |_| |  __\__ \
  \____|_| |_|\___/|___/\__|____/ \___|___/
                                           
    Python Cybersecurity Automation Tool v1.0
          By: zenyxsa
{Style.RESET_ALL}"""
    print(banner)

def save_results(tool_name, data, filename):
    """Saves output to either a .txt or .json file."""
    try:
        is_json = filename.lower().endswith('.json')
        mode = 'w' if is_json else 'a'
        
        with open(filename, mode) as f:
            if is_json:
                output = {
                    'tool': tool_name,
                    'timestamp': str(datetime.now()),
                    'data': data
                }
                json.dump(output, f, indent=4)
            else:
                f.write(f"\n--- {tool_name} Results [{datetime.now()}] ---\n")
                if isinstance(data, dict):
                    for k, v in data.items():
                        f.write(f"{k}: {v}\n")
                elif isinstance(data, list):
                    for item in data:
                        f.write(f"{item}\n")
                        
        print(f"{Fore.GREEN}[+] Results successfully saved to {filename}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to save results: {e}{Style.RESET_ALL}")

def check_host_up(target_ip):
    """Uses subprocess to ping the target and verify if it's reachable."""
    print(f"{Fore.CYAN}[i] Pinging {target_ip} to check if host is up...{Style.RESET_ALL}")
    # Adjust ping command based on the operating system
    if platform.system().lower() == 'windows':
        cmd = ['ping', '-n', '1', '-w', '1000', target_ip]
    else:
        cmd = ['ping', '-c', '1', '-W', '1', target_ip]
        
    try:
        output = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return output.returncode == 0
    except Exception:
        return False

def port_scanner(target, start_port, end_port, save_file=None):
    """Scans for open ports sequentially on a target using threads."""
    print(f"\n{Fore.YELLOW}[*] Starting Port Scan on {target} ({start_port}-{end_port})...{Style.RESET_ALL}")
    open_ports = []
    
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{Fore.RED}[!] Invalid target hostname/IP.{Style.RESET_ALL}")
        return

    print(f"{Fore.CYAN}[i] Target IP resolved: {target_ip}{Style.RESET_ALL}")
    
    if not check_host_up(target_ip):
        print(f"{Fore.YELLOW}[-] Host seems down or is blocking ping packets. Proceeding anyway...{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[+] Host is UP.{Style.RESET_ALL}")
        
    sys.stdout.write(f"{Fore.CYAN}[*] Scanning: ")
    sys.stdout.flush()

    def scan_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5) 
            if s.connect_ex((target_ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()
        
        # Loading animation
        if port % 20 == 0:
            sys.stdout.write(".")
            sys.stdout.flush()
            
        # Prevent spawning too many threads simultaneously (resource management)
        while threading.active_count() > 150:
            time.sleep(0.01)

    # Wait for all threads to finish
    for t in threads:
        t.join()

    print(f"\n\n{Fore.GREEN}[+] Port Scan Complete!{Style.RESET_ALL}")
    
    if open_ports:
        open_ports.sort()
        for port in open_ports:
            print(f"{Fore.GREEN}[+] Port {port} is OPEN{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[-] No open ports found in the specified range.{Style.RESET_ALL}")

    if save_file:
        save_results("Port Scan", {'target': target, 'open_ports': open_ports}, save_file)

def subdomain_finder(domain, wordlist_file=None, save_file=None):
    """Finds subdomains by appending common words to the target domain and resolving."""
    print(f"\n{Fore.YELLOW}[*] Starting Subdomain Finder for: {domain}{Style.RESET_ALL}")
    valid_subdomains = []
    
    # Minimal predefined list for quick scans
    words = ['www', 'mail', 'ftp', 'm', 'blog', 'dev', 'admin', 'test', 'api', 'portal', 'stage']
    
    if wordlist_file:
        try:
            with open(wordlist_file, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Wordlist file '{wordlist_file}' not found. Defaulting to built-in list.{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}[*] Testing {len(words)} potential subdomains...{Style.RESET_ALL}")
    
    for word in words:
        target = f"{word}.{domain}"
        sys.stdout.write(f"\rTesting: {target}" + " " * 20)
        sys.stdout.flush()
        try:
            ip = socket.gethostbyname(target)
            print(f"\r{Fore.GREEN}[+] Discovered: {target} -> {ip}{Style.RESET_ALL}" + " " * 10)
            valid_subdomains.append({'subdomain': target, 'ip': ip})
        except socket.gaierror:
            pass

    print() # Formatting newline
    if not valid_subdomains:
        print(f"{Fore.YELLOW}[-] No subdomains were discovered.{Style.RESET_ALL}")

    if save_file:
        save_results("Subdomain Finder", {'domain': domain, 'subdomains': valid_subdomains}, save_file)

def password_strength(password):
    """Evaluates password strength based on length and character sets using RegEx."""
    print(f"\n{Fore.YELLOW}[*] Evaluating Password Strength...{Style.RESET_ALL}")
    
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Increase length to at least 8 characters.")
        
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Include uppercase letters (A-Z).")
        
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Include lowercase letters (a-z).")
        
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Include numbers (0-9).")
        
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        score += 1
    else:
        feedback.append("Include special characters (e.g. !@#$%).")

    print(f"{Fore.CYAN}Total Score: {score}/5{Style.RESET_ALL}")
    
    if score >= 4:
        print(f"{Fore.GREEN}[+] STRENGTH: Strong{Style.RESET_ALL}")
    elif score == 3:
        print(f"{Fore.YELLOW}[~] STRENGTH: Moderate{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] STRENGTH: Weak{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Suggestions to improve:{Style.RESET_ALL}")
        for error in feedback:
            print(f"  - {error}")

def get_processor():
    if platform.system() == "Linux":
        try:
            with open("/proc/cpuinfo", "r") as cpuinfo:
                for line in cpuinfo:
                    if line.startswith(("model name", "Hardware")):
                        return line.split(":", 1)[1].strip()
        except (OSError, IndexError):
            pass
    return platform.processor() or "Unknown"

def system_info(save_file=None):
    """Gathers OS and network information of the currently running machine."""
    print(f"\n{Fore.YELLOW}[*] Gathering Target System Information...{Style.RESET_ALL}")
    
    try:
        info = {
            'Operating System': platform.system(),
            'OS Release': platform.release(),
            'OS Version': platform.version(),
            'Architecture': platform.machine(),
            'Processor': get_processor(),
            'Python Version': platform.python_version(),
            'Hostname': socket.gethostname(),
            'Local IP Address': socket.gethostbyname(socket.gethostname()),
        }
        
        for key, value in info.items():
            print(f"{Fore.CYAN}{key}: {Style.RESET_ALL}{value}")
            
        if save_file:
            save_results("System Information", info, save_file)
            
    except Exception as e:
        print(f"{Fore.RED}[!] Error gathering system info: {e}{Style.RESET_ALL}")

def log_analyzer(log_file, save_file=None):
    """Parses a text log file and flags lines matching suspicious keywords."""
    print(f"\n{Fore.YELLOW}[*] Analyzing Logs from: {log_file}{Style.RESET_ALL}")
    
    keywords = ["failed", "error", "unauthorized", "critical", "denied", "exception", "malicious"]
    suspicious_lines = []
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        print(f"{Fore.CYAN}[i] Total lines analyzed: {len(lines)}{Style.RESET_ALL}")
        
        for num, line in enumerate(lines, 1):
            line_lower = line.lower()
            for kw in keywords:
                if kw in line_lower:
                    suspicious_lines.append(f"Line {num} [{kw.upper()}]: {line.strip()}")
                    break
                    
        if suspicious_lines:
            print(f"{Fore.RED}[!] Discovered {len(suspicious_lines)} potential security incidents:{Style.RESET_ALL}")
            # Limit output to 15 to avoid console flooding
            for entry in suspicious_lines[:15]:
                print(entry)
            if len(suspicious_lines) > 15:
                print(f"... and {len(suspicious_lines) - 15} more records.")
        else:
            print(f"{Fore.GREEN}[+] Log appears clean. No suspicious entries matched.{Style.RESET_ALL}")
            
        if save_file:
            save_results("Log Analyzer", {'log_file': log_file, 'findings': suspicious_lines}, save_file)

    except FileNotFoundError:
        print(f"{Fore.RED}[!] Could not locate log file '{log_file}'.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading log file: {e}{Style.RESET_ALL}")

def interactive_menu():
    """Provides a Hacker-style CLI loop if arguments are omitted."""
    while True:
        # Clear terminal screen
        os.system('cls' if os.name == 'nt' else 'clear')
        print_banner()
        print(f"{Fore.CYAN}[ Interactive Mode ]{Style.RESET_ALL}\n")
        print("  1) Port Scanner")
        print("  2) Subdomain Finder")
        print("  3) Password Strength Checker")
        print("  4) System Information Gatherer")
        print("  5) Simple Log Analyzer")
        print("  6) URL Risk Detector")
        print("  7) Breach Exposure OSINT")
        print("  0) Exit\n")
        
        choice = input(f"{Fore.RED}zenyxsa@kali{Style.RESET_ALL}:{Fore.BLUE}~{Style.RESET_ALL}# ").strip()
        
        if choice == '1':
            target = input("Enter target IP or hostname (e.g. 192.168.1.1): ").strip()
            try:
                start = int(input("Start port (default 1) [Press Enter]: ") or 1)
                end = int(input("End port (default 1024) [Press Enter]: ") or 1024)
                save_prompt = input("Save results to file? (leave empty to skip): ").strip()
                port_scanner(target, start, end, save_prompt if save_prompt else None)
            except ValueError:
                print(f"{Fore.RED}[!] Invalid port number.{Style.RESET_ALL}")
                
        elif choice == '2':
            domain = input("Enter target domain (e.g. example.com): ").strip()
            wordlist = input("Wordlist path (leave empty for default): ").strip()
            save_prompt = input("Save results to file? (leave empty to skip): ").strip()
            subdomain_finder(domain, wordlist if wordlist else None, save_prompt if save_prompt else None)
            
        elif choice == '3':
            import getpass
            password = getpass.getpass("Enter password to evaluate (input hidden): ")
            password_strength(password)
            
        elif choice == '4':
            save_prompt = input("Save results to file? (leave empty to skip): ").strip()
            system_info(save_prompt if save_prompt else None)
            
        elif choice == '5':
            logfile = input("Enter absolute or relative path to log file: ").strip()
            save_prompt = input("Save results to file? (leave empty to skip): ").strip()
            log_analyzer(logfile, save_prompt if save_prompt else None)
            
        elif choice == '6':
            target_url = input("Enter URL to analyze: ").strip()
            result = analyze_url(target_url)
            print_url_report(result)
            save_prompt = input("Save report to file? (leave empty to skip): ").strip()
            if save_prompt:
                save_results("URL Risk Detector", result, save_prompt)

        elif choice == '7':
            account = input("Enter email/account identifier to check: ").strip()
            result = breach_lookup(account)
            print_breach_report(result)
            save_prompt = input("Save report to file? (leave empty to skip): ").strip()
            if save_prompt:
                save_results("Breach Exposure OSINT", result, save_prompt)

        elif choice == '0':
            print(f"\n{Fore.GREEN}[*] Shutting down. Stay stealthy!{Style.RESET_ALL}")
            sys.exit(0)
            
        else:
            print(f"{Fore.RED}[!] Command not recognized.{Style.RESET_ALL}")
            
        input(f"\n{Fore.CYAN}Press [ENTER] to return to the main menu...{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="GhostSec - Python Cybersecurity Automation Tool")
    parser.add_argument('-i', '--interactive', action='store_true', help='Open Interactive Hacker CLI Menu')
    
    subparsers = parser.add_subparsers(dest='command', help='Available Tools')
    
    # 1. Port Scanner
    scan_parser = subparsers.add_parser('scan', help='Port Scanner Module')
    scan_parser.add_argument('target', help='Target IP address or hostname')
    scan_parser.add_argument('-s', '--start', type=int, default=1, help='Start port (default: 1)')
    scan_parser.add_argument('-e', '--end', type=int, default=1024, help='End port (default: 1024)')
    scan_parser.add_argument('-o', '--output', help='Save output (supports .txt or .json)')

    # 2. Subdomain Finder
    sub_parser = subparsers.add_parser('subdomain', help='Subdomain Finder Module')
    sub_parser.add_argument('domain', help='Target domain (e.g., example.com)')
    sub_parser.add_argument('-w', '--wordlist', help='Custom dictionary wordlist file path')
    sub_parser.add_argument('-o', '--output', help='Save output (supports .txt or .json)')

    # 3. Password Strength
    pass_parser = subparsers.add_parser('passwd', help='Password Strength Checker')
    pass_parser.add_argument('password', help='Password string to evaluate')

    # 4. System Information
    info_parser = subparsers.add_parser('sysinfo', help='System Information Gatherer Module')
    info_parser.add_argument('-o', '--output', help='Save output (supports .txt or .json)')

    # 5. Log Analyzer
    log_parser = subparsers.add_parser('log', help='Simple Log Analyzer Module')
    log_parser.add_argument('file', help='Target log file to analyze (.txt, .log)')
    log_parser.add_argument('-o', '--output', help='Save output (supports .txt or .json)')
    # 6. URL Risk Detector
    url_parser = subparsers.add_parser('url', help='URL safety and reputation analysis')
    url_parser.add_argument('url', help='URL to analyze')
    url_parser.add_argument('-o', '--output', help='Save output (supports .txt or .json)')
    url_parser.add_argument('--no-urlhaus', action='store_true', help='Skip URLhaus reputation check')

    # 7. Breach Exposure OSINT
    breach_parser = subparsers.add_parser('breach', help='Check public breach exposure metadata')
    breach_parser.add_argument('account', help='Email/account identifier')
    breach_parser.add_argument('-o', '--output', help='Save output (supports .txt or .json)')


    args = parser.parse_args()

    # Drop into interactive menu if no arguments are passed or -i is used
    if len(sys.argv) == 1 or args.interactive:
        interactive_menu()
        return

    # Direct Command Line Usage
    print_banner()
    if args.command == 'scan':
        port_scanner(args.target, args.start, args.end, args.output)
    elif args.command == 'subdomain':
        subdomain_finder(args.domain, args.wordlist, args.output)
    elif args.command == 'passwd':
        password_strength(args.password)
    elif args.command == 'sysinfo':
        system_info(args.output)
    elif args.command == 'log':
        log_analyzer(args.file, args.output)
    elif args.command == 'url':
        result = analyze_url(args.url, check_urlhaus=not args.no_urlhaus)
        print_url_report(result)
        if args.output:
            save_results('URL Risk Detector', result, args.output)
    elif args.command == 'breach':
        result = breach_lookup(args.account)
        print_breach_report(result)
        if args.output:
            save_results('Breach Exposure OSINT', result, args.output)

if __name__ == "__main__":
    main()
