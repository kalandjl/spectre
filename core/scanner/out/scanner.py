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

    import argparse
    
    def main():
    
        parser = argparse.ArgumentParser(
            prog="spectre-scanner",
            description="Scanner tool for spectre, which collects network diagnostics for intel proccessing.",
            epilog="Use 'syn-apse <command> --help' for more information on a specific command."
        )    
    
        subparsers = parser.add_subparsers(dest="command", required=True, help="Avaliable commands")
    
        parser_scan = subparsers.add_parser('scan', 'Collect diagnostics given a network')
    
        parser_scan.add_argument(
           '-t', '--target',
           required=True,
           help="The network to scan on. (IP/CIDR/hostname)"
        )
        parser_scan.add_argument(
           '-o', '--output',
           required=False,
           help="Output filename (default: scan_TIMESTAMP.csv)"
        )
        parser_scan.add_argument(
           '-f', '--format',
           required=False,
           help="csv/json (default: csv)"
        )
        parser_scan.add_argument(
           '-r', '--port-range',
           required=False,
           help='Port range (default: top 1000)',
        )
        parser_scan.add_argument(
           '-s', '--timeout',
           required=False,
           help='Scan timeout (default: 10 min)'
        )
        parser_scan.add_argument(
           '-v', '--verbose',
           required=False,
           help="Verbose output (default: True)"
        )
    
        args = parser.parse_args()
    
    
        if args.command == "scan":
            try:
                # Start scanning logic
                print("[SCANNER] scanning...")
            except PermissionError:
                print("[ERROR] Permission denied. Packet sniffing requires root privileges. Try running with 'sudo'.")
            except Exception as e:
                print(f"[ERROR] An unexpected error occurred: {e}")
    
                
    if __name__ == "__main__":
        main()
    