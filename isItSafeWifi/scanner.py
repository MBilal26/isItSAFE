import subprocess
import re
import os
import sys
from typing import Dict, List

# Logger integration
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs"))
try:
    from logger import log_event
except ImportError:
    def log_event(m, msg, l="info"): pass

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

    def clear_networks(self):
        self.networks = {}
    
    def scan_networks(self) -> Dict[str, Dict]:
        if self.paused:
            return self.networks
        self.is_scanning = True
        try:
            # Force Windows to search for new networks (non-blocking)
            subprocess.run('netsh wlan scan', shell=True, capture_output=True, creationflags=0x08000000, timeout=5)
            
            output = subprocess.check_output(
                'netsh wlan show networks mode=bssid',
                shell=True,
                creationflags=0x08000000,
                timeout=15
            ).decode('ascii', errors='ignore')
            
            new_networks = {}
            # Split by SSID blocks
            ssid_blocks = re.split(r"SSID \d+ : ", output)[1:]
            
            for block in ssid_blocks:
                lines = block.split('\n')
                if not lines: continue
                ssid = lines[0].strip() or "[Hidden]"
                
                # Extract global network info from the block
                auth_match = re.search(r"Authentication\s+: (.*?)\n", block)
                encrypt_match = re.search(r"Encryption\s+: (.*?)\n", block)
                auth = auth_match.group(1).strip() if auth_match else ""
                encrypt = encrypt_match.group(1).strip() if encrypt_match else ""
                
                # Find all BSSIDs in this block
                bssids = re.findall(r"BSSID \d+\s+: (.*?)\n\s+Signal\s+: (.*?)\n", block)
                
                for bssid_val, signal_val in bssids:
                    bssid = bssid_val.strip().upper()
                    new_networks[bssid] = {
                        "SSID": ssid,
                        "Signal": signal_val.strip().replace('%', ''),
                        "Auth": auth,
                        "Encrypt": encrypt
                    }
            self.networks = new_networks
        except Exception as e:
            print(f"Scan error: {e}")
        self.is_scanning = False
        return self.networks

    def detect_evil_twins(self) -> Dict[str, Dict]:
        ssid_map: Dict[str, List[Dict]] = {}
        threats = {} # Format: {ssid: {"type": "mismatch"|"duplicate", "bssids": [...]}}
        
        # 1. Group BSSIDs by SSID
        for bssid, data in self.networks.items():
            ssid = data.get("SSID", "[Hidden]")
            if ssid == "[Hidden]": continue
            
            if ssid not in ssid_map:
                ssid_map[ssid] = []
            
            # Store data with BSSID for comparison
            entry = data.copy()
            entry["BSSID"] = bssid
            ssid_map[ssid].append(entry)
        
        # 2. Categorize Threats
        for ssid, nodes in ssid_map.items():
            if len(nodes) < 2: continue
            
            # Check for security profile mismatches
            first_node = nodes[0]
            mismatch_found = False
            for i in range(1, len(nodes)):
                if (nodes[i]["Auth"] != first_node["Auth"] or 
                    nodes[i]["Encrypt"] != first_node["Encrypt"]):
                    mismatch_found = True
                    break
            
            if mismatch_found:
                threats[ssid] = {"type": "mismatch", "bssids": [n["BSSID"] for n in nodes]}
            else:
                threats[ssid] = {"type": "duplicate", "bssids": [n["BSSID"] for n in nodes]}
        
        return threats

class NetworkBlocker:
    @staticmethod
    def block_ssid(ssid: str) -> bool:
        if not ssid or ssid == "[Hidden]": return False
        try:
            log_event("Blocker", f"Attempting to block SSID: {ssid}", "warning")
            cmd = f'netsh wlan add filter permission=block ssid="{ssid}" networktype=infrastructure'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, creationflags=0x08000000, timeout=10)
            
            if result.returncode == 0:
                log_event("Blocker", f"Successfully blocked SSID: {ssid}")
                return True
            else:
                log_event("Blocker", f"Failed to block {ssid}. Error: {result.stderr.strip() or result.stdout.strip()}", "error")
                return False
        except Exception as e:
            log_event("Blocker", f"Exception during block {ssid}: {str(e)}", "error")
            return False

    @staticmethod
    def unblock_ssid(ssid: str) -> bool:
        if not ssid: return False
        try:
            log_event("Blocker", f"Unblocking SSID: {ssid}")
            cmd = f'netsh wlan delete filter permission=block ssid="{ssid}" networktype=infrastructure'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, creationflags=0x08000000, timeout=10)
            
            if result.returncode == 0:
                log_event("Blocker", f"Successfully unblocked SSID: {ssid}")
                return True
            else:
                log_event("Blocker", f"Failed to unblock {ssid}. Error: {result.stderr.strip() or result.stdout.strip()}", "error")
                return False
        except Exception as e:
            log_event("Blocker", f"Exception during unblock {ssid}: {str(e)}", "error")
            return False