#!/usr/bin/env python
import contextlib as __stickytape_contextlib

@__stickytape_contextlib.contextmanager
def __stickytape_temporary_dir():
    import tempfile
    import shutil
    dir_path = tempfile.mkdtemp()
    try:
        yield dir_path
    finally:
        shutil.rmtree(dir_path)

with __stickytape_temporary_dir() as __stickytape_working_dir:
    def __stickytape_write_module(path, contents):
        import os, os.path

        def make_package(path):
            parts = path.split("/")
            partial_path = __stickytape_working_dir
            for part in parts:
                partial_path = os.path.join(partial_path, part)
                if not os.path.exists(partial_path):
                    os.mkdir(partial_path)
                    with open(os.path.join(partial_path, "__init__.py"), "wb") as f:
                        f.write(b"\n")

        make_package(os.path.dirname(path))

        full_path = os.path.join(__stickytape_working_dir, path)
        with open(full_path, "wb") as module_file:
            module_file.write(contents)

    import sys as __stickytape_sys
    __stickytape_sys.path.insert(0, __stickytape_working_dir)

    __stickytape_write_module('utils/__init__.py', b'')
    __stickytape_write_module('utils/str.py', b'from colorama import init, Fore, Style\nfrom datetime import datetime\n\ndef print_banner():\n    """Print ASCII banner"""\n    banner = f"""{Fore.CYAN}\n\xe2\x95\x94\xe2\x95\x90\xe2\x95\x97\xe2\x95\x94\xe2\x95\x90\xe2\x95\x97\xe2\x95\x94\xe2\x95\x90\xe2\x95\x97\xe2\x95\x94\xe2\x95\x90\xe2\x95\x97\xe2\x95\x94\xe2\x95\xa6\xe2\x95\x97\xe2\x95\xa6\xe2\x95\x90\xe2\x95\x97\xe2\x95\x94\xe2\x95\x90\xe2\x95\x97\n\xe2\x95\x9a\xe2\x95\x90\xe2\x95\x97\xe2\x95\xa0\xe2\x95\x90\xe2\x95\x9d\xe2\x95\x91\xe2\x95\xa3 \xe2\x95\x91   \xe2\x95\x91 \xe2\x95\xa0\xe2\x95\xa6\xe2\x95\x9d\xe2\x95\x91\xe2\x95\xa3 \n\xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d\xe2\x95\xa9  \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d\xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d \xe2\x95\xa9 \xe2\x95\xa9\xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d\n{Fore.WHITE}Network Vulnerability Scanner\n{Style.RESET_ALL}"""\n    print(banner)\n\n\ndef validate_target(target):\n    """Basic target validation"""\n    # Add validation logic here\n    return True\n\ndef generate_output_filename(format=\'csv\'):\n    """Generate default output filename with timestamp"""\n    timestamp = datetime.now().strftime(\'%Y%m%d_%H%M%S\')\n    return f"scan_{timestamp}.{format}"')
    __stickytape_write_module('modules/scanner.py', b'\nclass NetworkScanner:\n\n    def __init__(self, verbose):\n\n        self.verbose = verbose\n    \n    def scan(self, target, ports, timeout, rate_limit):\n\n\n        # Initialize results to prevent NoneType error\n        results = {}\n        print(f"[SCANNER] Scanner started on {target}:{ports}")\n\n        # Scanning logic\n\n        return results\n        ')
    __stickytape_write_module('utils/helpers.py', b'\ndef check_dependencies():\n\n    # Check if proper deps are installed (nmap, etc..)\n    return True')
    __stickytape_write_module('utils/parser.py', b'\ndef save_as_json(results, outDir):\n\n    print(f"[PARSER] Saving results file as {outDir}.json")\n\n    # Saving logic\n    \n    print(f"[PARSER] Successfully saved {outDir}.json")\n    \n\ndef save_as_csv(results, outDir):\n\n    print(f"[PARSER] Saving results file as {outDir}.csv")\n\n    # Saving logic\n        \n    print(f"[PARSER] Successfully saved {outDir}.json")\n')
    import argparse
    from utils import str
    import sys
    import os
    from datetime import datetime
    from colorama import init, Fore, Style
    
    def main():
    
        str.print_banner()
        
        parser = argparse.ArgumentParser(
            prog="spectre-scanner",
            description="Scanner tool for SPECTRE, which collects network diagnostics for vulnerability analysis.",
            epilog="Example: spectre-scanner scan -t 192.168.1.0/24 -o results.csv"
        )
        
        subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")
        
        # Scan command
        parser_scan = subparsers.add_parser('scan', help='Scan a network for services and vulnerabilities')
        
        parser_scan.add_argument(
            '-t', '--target',
            required=True,
            help="Target to scan (IP/CIDR/hostname). Examples: 192.168.1.1, 192.168.1.0/24, scanme.nmap.org"
        )
        
        parser_scan.add_argument(
            '-o', '--output',
            default=None,
            help="Output filename (default: scan_TIMESTAMP.csv)"
        )
        
        parser_scan.add_argument(
            '-f', '--format',
            choices=['csv', 'json'],
            default='csv',
            help="Output format (default: csv)"
        )
        
        parser_scan.add_argument(
            '-p', '--ports',
            default='top1000',
            help='Port specification (default: top1000). Examples: 1-1000, 80,443,8080, all'
        )
        
        parser_scan.add_argument(
            '--timeout',
            type=int,
            default=300,
            help='Scan timeout in seconds (default: 300)'
        )
    
        parser_scan.add_argument(
            '-v', '--verbose',
            action='store_true',
            help="Enable verbose output"
        )
        
        parser_scan.add_argument(
            '--rate',
            type=int,
            default=1000,
            help='Packets per second rate limit (default: 1000)'
        )
    
        # Future commands
        # parser_report = subparsers.add_parser('report', help='Generate report from scan')
        
        args = parser.parse_args()
    
    
        # SCANNING CLI LOGIC
        if args.command == "scan":
    
            # Handle commands
            if not args.output:
                args.output = str.generate_output_filename(args.format)
    
            # If target is not a valid target str
            if not str.validate_target(args.target):
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Invalid target: {args.target}")
                sys.exit(1)
    
    
    
            try:
                from modules.scanner import NetworkScanner
                from utils.helpers import check_dependencies
                
                # Check if nmap is installed
                if not check_dependencies():
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} nmap is not installed. Please install it first.")
                    print(f"  Ubuntu/Debian: sudo apt-get install nmap")
                    print(f"  MacOS: brew install nmap")
                    print(f"  RHEL/CentOS: sudo yum install nmap")
                    sys.exit(1)
                
                # Start scanning
                print(f"{Fore.GREEN}[SCANNER]{Style.RESET_ALL} Starting scan of {args.target}")
                if args.verbose:
                    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Output file: {args.output}")
                    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Port range: {args.ports}")
                    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Timeout: {args.timeout}s")
                
                scanner = NetworkScanner(verbose=args.verbose)
                results = scanner.scan(
                    target=args.target,
                    ports=args.ports,
                    timeout=args.timeout,
                    rate_limit=args.rate
                )
                
                # Save results
                if args.format == 'csv':
                    from utils.parser import save_as_csv
                    save_as_csv(results, args.output)
                else:
                    from utils.parser import save_as_json
                    save_as_json(results, args.output)
                
                # Print summary
                print(f"\n{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Scan completed!")
                print(f"  • Hosts scanned: {len(set(r['target_ip'] for r in results))}")
                print(f"  • Services found: {len(results)}")
                print(f"  • Results saved to: {args.output}")
                print(f"\n📤 Upload your scan at: {Fore.CYAN}https://spectre.dev/upload{Style.RESET_ALL}")
                
            except PermissionError:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Permission denied. Network scanning requires root privileges.")
                print(f"Try running with: {Fore.YELLOW}sudo python {' '.join(sys.argv)}{Style.RESET_ALL}")
                sys.exit(1)
                
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[INTERRUPTED]{Style.RESET_ALL} Scan cancelled by user")
                sys.exit(0)
                
            except Exception as e:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} An unexpected error occurred: {e}")
                if args.verbose:
                    import traceback
                    traceback.print_exc()
                sys.exit(1)
    
                
    if __name__ == "__main__":
        main()
    