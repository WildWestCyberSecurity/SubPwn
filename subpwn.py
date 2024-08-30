#!/usr/bin/env python3

import argparse
import subprocess
import json
import os
import logging
import sys
import time
import threading
import itertools
from colorama import Fore, Style, init
import dns.resolver
import dns.zone
import dns.exception
import dns.query
import concurrent.futures
import requests
from urllib3.exceptions import InsecureRequestWarning
import socket
import re
import signal
import queue

# Initialize colorama for cross-platform colored output
init()

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def setup_logging(output_dir):
    log_file = os.path.join(output_dir, 'subpwn.log')
    logging.basicConfig(filename=log_file, level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def loading_animation(stop_event, desc="Processing"):
    animation = itertools.cycle(['/   ', '-   ', '\\   ', '|   ',
                                 ' /  ', ' -  ', ' \\  ', ' |  ',
                                 '  / ', '  - ', '  \\ ', '  | ',
                                 '   /', '   -', '   \\', '   |'])
    while not stop_event.is_set():
        print(f"\r{Fore.YELLOW}{desc} {next(animation)}{Style.RESET_ALL}", end='', flush=True)
        time.sleep(0.1)
    print("\r" + " " * (len(desc) + 5), end='\r')  # Clear the animation line

def run_command(command, desc):
    try:
        stop_event = threading.Event()
        animation_thread = threading.Thread(target=loading_animation, args=(stop_event, desc))
        animation_thread.start()

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
        output = []
        for line in process.stdout:
            output.append(line.strip())
        process.wait()

        stop_event.set()
        animation_thread.join()

        if process.returncode != 0:
            print(f"{Fore.RED}Error running {desc}: {process.stderr.read()}{Style.RESET_ALL}")
            logging.error(f"Error running {desc}: {process.stderr.read()}")
        else:
            print(f"{Fore.GREEN}{desc} completed successfully{Style.RESET_ALL}")
        return output
    except Exception as e:
        stop_event.set()
        animation_thread.join()
        print(f"{Fore.RED}Exception occurred while running {desc}: {str(e)}{Style.RESET_ALL}")
        logging.exception(f"Exception occurred while running {desc}")
        return []

def passive_enumeration(domain, api_key=None, fast_mode=False):
    subdomains = set()

    print(f"{Fore.CYAN}Phase 1: Passive Subdomain Enumeration{Style.RESET_ALL}")
    logging.info("Starting Phase 1: Passive Subdomain Enumeration")

    # Sublist3r
    print(f"{Fore.YELLOW}Running Sublist3r...{Style.RESET_ALL}")
    sublist3r_cmd = f"sublist3r -d {domain} -o sublist3r_output.txt -t 50 -v"
    sublist3r_output = run_command(sublist3r_cmd, "Sublist3r")
    sublist3r_subdomains = set(sublist3r_output)
    subdomains.update(sublist3r_subdomains)
    print(f"{Fore.MAGENTA}Found {len(sublist3r_subdomains)} subdomains with Sublist3r!{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}So far we have found {len(subdomains)} unique subdomains!{Style.RESET_ALL}")

    # Subfinder
    print(f"{Fore.YELLOW}Running Subfinder...{Style.RESET_ALL}")
    subfinder_cmd = f"subfinder -d {domain} -o subfinder_output.txt -t 100 -nW"
    if fast_mode:
        subfinder_cmd += " -timeout 10"
    subfinder_output = run_command(subfinder_cmd, "Subfinder")
    subfinder_subdomains = set(subfinder_output)
    new_subdomains = subfinder_subdomains - subdomains
    subdomains.update(subfinder_subdomains)
    print(f"{Fore.MAGENTA}Found {len(subfinder_subdomains)} subdomains with Subfinder ({len(new_subdomains)} new)!{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}So far we have found {len(subdomains)} unique subdomains!{Style.RESET_ALL}")

    # SecurityTrails (if API key provided)
    if api_key:
        print(f"{Fore.YELLOW}Querying SecurityTrails...{Style.RESET_ALL}")
        securitytrails_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"apikey": api_key.strip('"')}  # Remove quotes from API key
        try:
            response = requests.get(securitytrails_url, headers=headers)
            response.raise_for_status()  # Raise an exception for bad status codes
            data = response.json()

            if "subdomains" in data:
                securitytrails_subdomains = set(f"{sub}.{domain}" for sub in data["subdomains"])
                new_subdomains = securitytrails_subdomains - subdomains
                subdomains.update(securitytrails_subdomains)
                print(f"{Fore.MAGENTA}Found {len(securitytrails_subdomains)} subdomains with SecurityTrails ({len(new_subdomains)} new)!{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}So far we have found {len(subdomains)} unique subdomains!{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}No subdomains found in SecurityTrails response.{Style.RESET_ALL}")

            if "subdomain_count" in data:
                print(f"{Fore.MAGENTA}SecurityTrails reports a total of {data['subdomain_count']} subdomains for this domain.{Style.RESET_ALL}")

        except requests.RequestException as e:
            print(f"{Fore.RED}Error querying SecurityTrails API: {str(e)}{Style.RESET_ALL}")
            logging.error(f"Error querying SecurityTrails API: {str(e)}")
    else:
        print(f"{Fore.YELLOW}Skipping SecurityTrails fetch (no API key provided){Style.RESET_ALL}")
        logging.info("Skipping SecurityTrails fetch (no API key provided)")

    print(f"{Fore.CYAN}Phase 1 completed. Total unique subdomains found: {len(subdomains)}{Style.RESET_ALL}")
    return list(subdomains)

def dns_enumerate(domain, wordlist, fast_mode=False, output_dir=None, save_interval=50):
    print(f"{Fore.CYAN}Phase 2: Active Subdomain Enumeration (DNS){Style.RESET_ALL}")
    logging.info("Starting Phase 2: Active Subdomain Enumeration")

    threads = 50 if fast_mode else 20
    print(f"{Fore.YELLOW}Using {threads} threads for DNS enumeration{Style.RESET_ALL}")

    resume_file = os.path.join(output_dir, f"{domain}_dns_progress.json")
    output_file = os.path.join(output_dir, f"{domain}_dns_output.txt")
    
    # Load progress if exists
    start_index = 0
    subdomains = set()
    if os.path.exists(resume_file):
        with open(resume_file, 'r') as f:
            progress_data = json.load(f)
            start_index = progress_data['index']
            subdomains = set(progress_data['subdomains'])
        print(f"{Fore.YELLOW}Resuming DNS enumeration from index: {start_index}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Loaded {len(subdomains)} previously discovered subdomains{Style.RESET_ALL}")

    with open(wordlist, 'r') as f:
        words = f.read().splitlines()[start_index:]

    total_words = len(words) + start_index
    current_index = start_index
    word_queue = queue.Queue()
    for word in words:
        word_queue.put(word)

    def check_subdomain():
        nonlocal current_index
        while True:
            try:
                word = word_queue.get_nowait()
            except queue.Empty:
                break
            subdomain = f"{word}.{domain}"
            try:
                dns.resolver.resolve(subdomain, 'A')
                return subdomain
            except dns.exception.DNSException:
                pass
            finally:
                current_index += 1
                if current_index % save_interval == 0:
                    save_progress()

    def save_progress():
        with open(resume_file, 'w') as f:
            json.dump({'index': current_index, 'subdomains': list(subdomains)}, f)
        print(f"\r{Fore.YELLOW}Progress: {current_index}/{total_words} words processed, {len(subdomains)} subdomains found{Style.RESET_ALL}", end='', flush=True)

    def signal_handler(signum, frame):
        print(f"\n{Fore.YELLOW}Interrupted! Saving DNS enumeration progress...{Style.RESET_ALL}")
        save_progress()
        sys.exit(0)

    original_sigint_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            while not word_queue.empty():
                futures = [executor.submit(check_subdomain) for _ in range(min(threads, word_queue.qsize()))]
                for future in concurrent.futures.as_completed(futures):
                    subdomain = future.result()
                    if subdomain:
                        subdomains.add(subdomain)
                        with open(output_file, 'a') as f:
                            f.write(f"{subdomain}\n")
                save_progress()

    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    finally:
        signal.signal(signal.SIGINT, original_sigint_handler)

    print(f"\n{Fore.MAGENTA}Found {len(subdomains)} subdomains with DNS enumeration!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Phase 2 completed. Total unique subdomains found: {len(subdomains)}{Style.RESET_ALL}")
    return list(subdomains)

def vhost_brute_force(domain, subdomains, wordlist, rate_limit, fast_mode=False, max_workers=10, output_dir=None):
    print(f"{Fore.CYAN}Phase 3: VHost Brute-Forcing (Improved){Style.RESET_ALL}")
    logging.info("Starting Phase 3: VHost Brute-Forcing (Improved)")

    ip_subdomain_map = {}
    cdn_providers = set(['cloudflare', 'akamai', 'fastly', 'amazon cloudfront', 'cdn77'])

    def resolve_subdomain(subdomain):
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            return subdomain, [rdata.address for rdata in answers]
        except dns.exception.DNSException as e:
            logging.warning(f"Failed to resolve IP for {subdomain}: {str(e)}")
            return subdomain, []

    # Resolve subdomains in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(resolve_subdomain, subdomains))

    for subdomain, ips in results:
        for ip in ips:
            if ip not in ip_subdomain_map:
                ip_subdomain_map[ip] = []
            ip_subdomain_map[ip].append(subdomain)

    vhosts = set()
    scanned_ips = set()

    resume_file = os.path.join(output_dir, f"{domain}_vhost_progress.json")
    progress = load_progress(resume_file) if os.path.exists(resume_file) else {}

    def scan_ip(ip, hosted_subdomains):
        if ip in scanned_ips:
            return []

        # Check if the IP belongs to a known CDN
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            if any(cdn in hostname for cdn in cdn_providers):
                print(f"{Fore.YELLOW}Skipping likely CDN IP: {ip} ({hostname}){Style.RESET_ALL}")
                return []
        except socket.herror:
            pass  # Couldn't resolve hostname, proceed with scanning

        print(f"{Fore.YELLOW}Brute-forcing VHosts for IP: {ip}{Style.RESET_ALL}")
        threads = 50 if fast_mode else 20
        
        resume_word = progress.get(ip)
        ffuf_output = os.path.join(output_dir, f"{domain}_ffuf_output_{ip}.json")
        ffuf_cmd = [
            "ffuf", "-w", wordlist, 
            "-u", f"http://{ip}", 
            "-H", f"Host: FUZZ.{domain}", 
            "-rate", str(rate_limit), 
            "-t", str(threads), 
            "-c", "-v", 
            "-o", ffuf_output, 
            "-of", "json",
            "-mc", "200,204,301,302,307,401,403,405", 
            "-fs", "0"
        ]
        if resume_word:
            ffuf_cmd.extend(["-sw", resume_word])
            print(f"{Fore.YELLOW}Resuming FFUF for IP {ip} from word: {resume_word}{Style.RESET_ALL}")
        if fast_mode:
            ffuf_cmd.extend(["-timeout", "2"])

        try:
            ffuf_process = subprocess.Popen(ffuf_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            current_word = ""
            for line in ffuf_process.stdout:
                if "| URL |" in line:
                    current_word = line.split("|")[2].strip()  # Assumes the word is in the third column

            ffuf_process.wait()

            try:
                with open(ffuf_output, 'r') as f:
                    ffuf_results = json.load(f)
                return [f"{result['input']['FUZZ']}.{domain}" for result in ffuf_results.get('results', []) if result.get('status') == 200]
            except json.JSONDecodeError:
                logging.error(f"Failed to parse FFUF output for IP {ip}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error running FFUF on {ip}: {e.output}")
            print(f"{Fore.RED}Error running FFUF on {ip}. Check the log for details.{Style.RESET_ALL}")

        return []

    # Run vhost scans in parallel
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(scan_ip, ip, hosted_subdomains): ip 
                            for ip, hosted_subdomains in ip_subdomain_map.items() 
                            if len(hosted_subdomains) > 1 and ip not in scanned_ips}

            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    new_vhosts = future.result()
                    vhosts.update(new_vhosts)
                    scanned_ips.add(ip)
                except Exception as exc:
                    print(f'{Fore.RED}Error scanning {ip}: {exc}{Style.RESET_ALL}')
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted! Saving VHost brute-force progress...{Style.RESET_ALL}")
        # Save progress here if needed
        sys.exit(0)

    print(f"{Fore.MAGENTA}Found {len(vhosts)} new virtual hosts!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Phase 3 completed. Total new virtual hosts found: {len(vhosts)}{Style.RESET_ALL}")
    return list(vhosts)

def dns_zone_transfer(domain):
    print(f"{Fore.CYAN}Phase 4: Intelligent DNS Zone Transfer Attempts{Style.RESET_ALL}")
    logging.info("Starting Phase 4: Intelligent DNS Zone Transfer Attempts")

    subdomains = set()
    transfer_attempted = set()

    def attempt_transfer(server, domain, transfer_type="AXFR"):
        if (server, domain, transfer_type) in transfer_attempted:
            return set()

        transfer_attempted.add((server, domain, transfer_type))
        print(f"{Fore.YELLOW}Attempting {transfer_type} transfer from {server}...{Style.RESET_ALL}")
        try:
            if transfer_type == "AXFR":
                z = dns.zone.from_xfr(dns.query.xfr(server, domain, lifetime=5))
            else:  # IXFR
                z = dns.zone.from_xfr(dns.query.xfr(server, domain, lifetime=5, use_udp=True))
            names = z.nodes.keys()
            new_subdomains = {f"{n}.{domain}".strip('.') for n in names if n != '@'}
            print(f"{Fore.GREEN}Successful {transfer_type} transfer from {server}!{Style.RESET_ALL}")
            logging.info(f"Successful {transfer_type} transfer from {server}")
            return new_subdomains
        except Exception as e:
            print(f"{Fore.YELLOW}{transfer_type} transfer failed for {server}: {str(e)}{Style.RESET_ALL}")
            logging.warning(f"{transfer_type} transfer failed for {server}: {str(e)}")
            return set()

    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        nameservers = [str(ns.target).rstrip('.') for ns in ns_records]

        soa_record = dns.resolver.resolve(domain, 'SOA')
        soa_mname = str(soa_record[0].mname).rstrip('.')

        all_nameservers = list(set(nameservers + [soa_mname]))

        for ns in all_nameservers:
            subdomains.update(attempt_transfer(ns, domain, "AXFR"))
            subdomains.update(attempt_transfer(ns, domain, "IXFR"))

        secondary_ns_attempts = [
            f"ns2.{domain}", f"sec.{domain}", f"secondary.{domain}",
            f"slave.{domain}", f"dns2.{domain}", f"backup.{domain}"
        ]

        for sec_ns in secondary_ns_attempts:
            try:
                ip = dns.resolver.resolve(sec_ns, 'A')[0].to_text()
                subdomains.update(attempt_transfer(ip, domain, "AXFR"))
                subdomains.update(attempt_transfer(ip, domain, "IXFR"))
            except dns.exception.DNSException:
                pass

    except dns.exception.DNSException as e:
        print(f"{Fore.RED}DNS query failed: {str(e)}{Style.RESET_ALL}")
        logging.error(f"DNS query failed: {str(e)}")

    print(f"{Fore.MAGENTA}Found {len(subdomains)} subdomains through DNS Zone Transfer!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Phase 4 completed. Total subdomains found through Zone Transfer: {len(subdomains)}{Style.RESET_ALL}")
    return list(subdomains)

def verify_subdomain(subdomain):
    try:
        response = requests.get(f"https://{subdomain}", timeout=5, verify=False)
        return subdomain, response.status_code
    except requests.RequestException:
        try:
            response = requests.get(f"http://{subdomain}", timeout=5)
            return subdomain, response.status_code
        except requests.RequestException:
            return subdomain, None

def verify_subdomains(subdomains, max_workers=20):
    print(f"{Fore.CYAN}Phase 5: Verifying Active Subdomains{Style.RESET_ALL}")
    logging.info("Starting Phase 5: Verifying Active Subdomains")

    active_subdomains = []
    stop_event = threading.Event()
    animation_thread = threading.Thread(target=loading_animation, args=(stop_event, "Verifying subdomains"))
    animation_thread.start()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_subdomain = {executor.submit(verify_subdomain, subdomain): subdomain for subdomain in subdomains}
        for future in concurrent.futures.as_completed(future_to_subdomain):
            subdomain = future_to_subdomain[future]
            try:
                subdomain, status_code = future.result()
                if status_code is not None:
                    active_subdomains.append((subdomain, status_code))
                    logging.info(f"Active subdomain: {subdomain} (Status: {status_code})")
                else:
                    logging.info(f"Inactive subdomain: {subdomain}")
            except Exception as exc:
                logging.error(f"Error verifying {subdomain}: {str(exc)}")

    stop_event.set()
    animation_thread.join()

    print(f"{Fore.GREEN}Subdomain verification completed{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}Active subdomains: {len(active_subdomains)}/{len(subdomains)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Phase 5 completed. Total active subdomains found: {len(active_subdomains)}{Style.RESET_ALL}")

    return active_subdomains

def is_valid_line(line):
    """Check if a line contains only valid domain characters."""
    return re.match(r'^[a-zA-Z0-9.-]+(\s\(Status:\s\d+\))?$', line.strip()) is not None

def clean_output_file(file_path):
    """Remove lines with unexpected characters from the output file."""
    logging.info(f"Cleaning output file: {file_path}")
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()

        original_count = len(lines)
        clean_lines = [line for line in lines if is_valid_line(line)]
        cleaned_count = len(clean_lines)

        with open(file_path, 'w') as f:
            f.writelines(clean_lines)

        logging.info(f"Cleaned output file: {file_path}")
        logging.info(f"Lines before cleaning: {original_count}, Lines after cleaning: {cleaned_count}")

        if original_count != cleaned_count:
            print(f"{Fore.YELLOW}Warning: {original_count - cleaned_count} lines were removed during cleaning of {file_path}{Style.RESET_ALL}")
    except IOError as e:
        print(f"{Fore.RED}Error cleaning file {file_path}: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Error cleaning file {file_path}: {str(e)}")

def update_subdomains_file(subdomains, output_file):
    with open(output_file, 'w') as f:
        for subdomain in sorted(set(subdomains)):
            if is_valid_line(subdomain):
                f.write(f"{subdomain}\n")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Subdomain Enumeration, VHost Brute-Forcing, and Active Subdomain Verification",
        epilog="Example usage:\n"
               "  python subpwn.py -d example.com -w wordlist.txt -o output_dir\n"
               "  python subpwn.py -dL domains.txt -w wordlist.txt -o output_dir --skip-p3\n"
               "  python subpwn.py -d example.com -o output_dir --skip-p2 --skip-p3",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-d", "--domain", help="Single domain for enumeration")
    target_group.add_argument("-dL", "--domain-list", help="Path to a file containing a list of domains")

    parser.add_argument("-w", "--wordlist", help="Path to a wordlist for subdomain and VHost brute-forcing")
    parser.add_argument("-api", "--api-key", help="SecurityTrails API key for additional passive enumeration")
    parser.add_argument("-o", "--output-dir", required=True, help="Directory to store output files")
    parser.add_argument("-FF", "--fast", action="store_true", help="Run all tools with maximum speed")
    parser.add_argument("--rate-limit", type=int, default=10, help="Rate limit for FFUF requests (requests per second)")
    parser.add_argument("--skip-p1", action="store_true", help="Skip Phase 1: Passive Enumeration")
    parser.add_argument("--skip-p2", action="store_true", help="Skip Phase 2: Active Enumeration")
    parser.add_argument("--skip-p3", action="store_true", help="Skip Phase 3: VHost Brute-Forcing")
    parser.add_argument("--skip-p4", action="store_true", help="Skip Phase 4: DNS Zone Transfer")
    parser.add_argument("--skip-p5", action="store_true", help="Skip Phase 5: Active Subdomain Verification")
    parser.add_argument("--max-workers", type=int, default=20, help="Maximum number of worker threads for subdomain verification and vhost scanning")
    parser.add_argument("--save-interval", type=int, default=50, help="Interval for saving progress in DNS enumeration (default: 50)")

    args = parser.parse_args()

    if not args.skip_p2 and not args.skip_p3 and not args.wordlist:
        parser.error("Wordlist (-w) is required when running active enumeration or VHost brute-forcing")

    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    setup_logging(args.output_dir)

    domains = []
    if args.domain:
        domains.append(args.domain)
    elif args.domain_list:
        with open(args.domain_list, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]

    for domain in domains:
        print(f"{Fore.CYAN}Processing domain: {Fore.GREEN}{domain}{Style.RESET_ALL}")
        logging.info(f"Processing domain: {domain}")

        all_subdomains = []
        output_file = os.path.join(args.output_dir, f"{domain}_subdomains.txt")

        output_file_base, output_file_ext = os.path.splitext(output_file)
        verified_output_file = f"{output_file_base}_verified{output_file_ext}"

        # Phase 1: Passive Enumeration
        if not args.skip_p1:
            passive_subdomains = passive_enumeration(domain, args.api_key, args.fast)
            all_subdomains.extend(passive_subdomains)
            update_subdomains_file(all_subdomains, output_file)
        else:
            print(f"{Fore.YELLOW}Skipping Phase 1: Passive Enumeration{Style.RESET_ALL}")
            logging.info("Skipping Phase 1: Passive Enumeration")

        # Phase 2: Active Enumeration
        if not args.skip_p2 and args.wordlist:
            active_subdomains = dns_enumerate(domain, args.wordlist, fast_mode=args.fast, output_dir=args.output_dir, save_interval=args.save_interval)
            new_subdomains = set(active_subdomains) - set(all_subdomains)
            all_subdomains.extend(new_subdomains)
            update_subdomains_file(all_subdomains, output_file)
            print(f"{Fore.MAGENTA}Found {len(new_subdomains)} new subdomains in Phase 2!{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}Total unique subdomains so far: {len(all_subdomains)}{Style.RESET_ALL}")
        else:
            if args.skip_p2:
                print(f"{Fore.YELLOW}Skipping Phase 2: Active Enumeration{Style.RESET_ALL}")
                logging.info("Skipping Phase 2: Active Enumeration")
            elif not args.wordlist:
                print(f"{Fore.YELLOW}Skipping Phase 2: Active Enumeration (no wordlist provided){Style.RESET_ALL}")
                logging.info("Skipping Phase 2: Active Enumeration (no wordlist provided)")

        # Phase 3: VHost Brute-Forcing
        if not args.skip_p3 and args.wordlist and all_subdomains:
            vhosts = vhost_brute_force(domain, all_subdomains, args.wordlist, args.rate_limit, args.fast, args.max_workers, args.output_dir)
            new_vhosts = set(vhosts) - set(all_subdomains)
            all_subdomains.extend(new_vhosts)
            update_subdomains_file(all_subdomains, output_file)
            print(f"{Fore.MAGENTA}Found {len(new_vhosts)} new virtual hosts in Phase 3!{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}Total unique subdomains so far: {len(all_subdomains)}{Style.RESET_ALL}")
        else:
            if args.skip_p3:
                print(f"{Fore.YELLOW}Skipping Phase 3: VHost Brute-Forcing{Style.RESET_ALL}")
                logging.info("Skipping Phase 3: VHost Brute-Forcing")
            elif not args.wordlist:
                print(f"{Fore.YELLOW}Skipping Phase 3: VHost Brute-Forcing (no wordlist provided){Style.RESET_ALL}")
                logging.info("Skipping Phase 3: VHost Brute-Forcing (no wordlist provided)")
            elif not all_subdomains:
                print(f"{Fore.YELLOW}Skipping Phase 3: VHost Brute-Forcing (no subdomains found){Style.RESET_ALL}")
                logging.info("Skipping Phase 3: VHost Brute-Forcing (no subdomains found)")

        # Phase 4: DNS Zone Transfer
        if not args.skip_p4:
            zone_transfer_subdomains = dns_zone_transfer(domain)
            new_zone_subdomains = set(zone_transfer_subdomains) - set(all_subdomains)
            all_subdomains.extend(new_zone_subdomains)
            update_subdomains_file(all_subdomains, output_file)
            print(f"{Fore.MAGENTA}Found {len(new_zone_subdomains)} new subdomains through DNS Zone Transfer in Phase 4!{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}Total unique subdomains so far: {len(all_subdomains)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Skipping Phase 4: DNS Zone Transfer{Style.RESET_ALL}")
            logging.info("Skipping Phase 4: DNS Zone Transfer")

        # Phase 5: Active Subdomain Verification
        if not args.skip_p5:
            active_subdomains = verify_subdomains(all_subdomains, args.max_workers)
            if active_subdomains:
                try:
                    verified_output_file_codes = f"{output_file_base}_verified_codes{output_file_ext}"
                    verified_output_file_clean = f"{output_file_base}_verified_clean{output_file_ext}"

                    with open(verified_output_file_codes, 'w') as f_codes, open(verified_output_file_clean, 'w') as f_clean:
                        for subdomain, status_code in active_subdomains:
                            f_codes.write(f"{subdomain} (Status: {status_code})\n")
                            f_clean.write(f"{subdomain}\n")

                    print(f"{Fore.GREEN}Verified subdomains with status codes saved to: {verified_output_file_codes}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}Clean verified subdomains saved to: {verified_output_file_clean}{Style.RESET_ALL}")
                    logging.info(f"Verified subdomains with status codes saved to: {verified_output_file_codes}")
                    logging.info(f"Clean verified subdomains saved to: {verified_output_file_clean}")

                    # Clean output files
                    clean_output_file(verified_output_file_codes)
                    clean_output_file(verified_output_file_clean)

                except IOError as e:
                    print(f"{Fore.RED}Error writing to files: {str(e)}{Style.RESET_ALL}")
                    logging.error(f"Error writing to files: {str(e)}")
            else:
                print(f"{Fore.YELLOW}No active subdomains found to save.{Style.RESET_ALL}")
                logging.warning("No active subdomains found to save.")
        else:
            print(f"{Fore.YELLOW}Skipping Phase 5: Active Subdomain Verification{Style.RESET_ALL}")
            logging.info("Skipping Phase 5: Active Subdomain Verification")

        print(f"{Fore.CYAN}Subdomain enumeration complete for {domain}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Total unique subdomains found: {len(set(all_subdomains))}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}All subdomains saved to: {output_file}{Style.RESET_ALL}")
        if not args.skip_p5 and active_subdomains:
            print(f"{Fore.MAGENTA}Total verified active subdomains: {len(active_subdomains)}{Style.RESET_ALL}")
        logging.info(f"Subdomain enumeration complete for {domain}")
        logging.info(f"Total unique subdomains found: {len(set(all_subdomains))}")
        logging.info(f"All subdomains saved to: {output_file}")
        if not args.skip_p5 and active_subdomains:
            logging.info(f"Total verified active subdomains: {len(active_subdomains)}")

if __name__ == "__main__":
    main()
