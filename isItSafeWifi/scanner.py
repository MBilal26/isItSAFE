import subprocess
import re
from typing import Dict, List

class NetworkScanner:
    def __init__(self):
        self.networks: Dict[str, Dict] = {}
        self.is_scanning = False
        self.paused = False
        
        self.pattern = re.compile(
            r"SSID \d+ : (.*?)\n.*?"
            r"Network type\s+: (.*?)\n.*?"
            r"Authentication\s+: (.*?)\n.*?"
            r"Encryption\s+: (.*?)\n.*?"
            r"BSSID 1\s+: (.*?)\n.*?"
            r"Signal\s+: (.*?)\n",
            re.DOTALL
        )
    
    def scan_networks(self) -> Dict[str, Dict]:
        if self.paused:
            return self.networks
        self.is_scanning = True
        try:
            output = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                shell=True,
                creationflags=0x08000000,
                timeout=15
            ).decode('ascii', errors='ignore')
            
            results = self.pattern.findall(output)
            new_networks = {}
            for ssid, net_type, auth, encrypt, bssid, signal in results:
                ssid = ssid.strip() or "[Hidden]"
                bssid = bssid.strip().upper()
                new_networks[bssid] = {
                    "SSID": ssid,
                    "Signal": signal.strip(),
                    "Auth": auth.strip(),
                    "Encrypt": encrypt.strip()
                }
            self.networks = new_networks
        except Exception as e:
            print(f"Scan error: {e}")
        self.is_scanning = False
        return self.networks

    def detect_evil_twins(self) -> Dict[str, List[str]]:
        ssid_map: Dict[str, List[str]] = {}
        threats = {}
        
        # 1. Detect multiple BSSIDs for same SSID
        for bssid, data in self.networks.items():
            ssid = data.get("SSID", "[Hidden]")
            if ssid not in ssid_map:
                ssid_map[ssid] = []
            ssid_map[ssid].append(bssid)
        
        # Find SSIDs with duplicate BSSIDs
        duplicates = {ssid: bssids for ssid, bssids in ssid_map.items() if len(bssids) > 1 and ssid != "[Hidden]"}
        
        # 2. Heuristic check: Open networks with same name as secure ones (common phishing)
        # (This is a future enhancement)
        
        return duplicates

class NetworkBlocker:
    @staticmethod
    def block_ssid(ssid: str) -> bool:
        try:
            log_event("Blocker", f"Attempting to block SSID: {ssid}", "warning")
            subprocess.run(
                ['netsh', 'wlan', 'add', 'filter', 'permission=denyall',
                 f'ssid="{ssid}"', 'networktype=infrastructure'],
                shell=True, creationflags=0x08000000, timeout=5, check=True
            )
            return True
        except Exception as e:
            log_event("Blocker", f"Failed to block {ssid}: {str(e)}", "error")
            return False

    @staticmethod
    def unblock_ssid(ssid: str) -> bool:
        try:
            log_event("Blocker", f"Unblocking SSID: {ssid}")
            subprocess.run(
                ['netsh', 'wlan', 'delete', 'filter', 'permission=denyall',
                 f'ssid="{ssid}"', 'networktype=infrastructure'],
                shell=True, creationflags=0x08000000, timeout=5, check=True
            )
            return True
        except Exception as e:
            log_event("Blocker", f"Failed to unblock {ssid}: {str(e)}", "error")
            return False