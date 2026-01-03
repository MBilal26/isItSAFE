import subprocess
import time
import sys
import os

def create_fake_wifi(ssid, password="Password123"):
    print(f"[*] Attemping to generate Evil Twin for: {ssid}")
    
    # Using PowerShell to create a mobile hotspot (Windows 10/11 approach)
    # Note: This requires a WiFi adapter that supports hosted networks/hotspots
    ps_script = f"""
    $MainSSID = "{ssid}"
    $Password = "{password}"
    
    try {{
        # This is a simulation - in a real attack, hardware would broadcast a duplicate SSID.
        # Here we attempt to trigger the Windows Hosted Network feature.
        netsh wlan set hostednetwork mode=allow ssid=$MainSSID key=$Password
        netsh wlan start hostednetwork
        Write-Host "Evil Twin Simulation Active: $MainSSID"
    }} catch {{
        Write-Error "Hardware may not support netsh hostednetwork. Modern Windows uses Mobile Hotspot API."
    }}
    """
    
    try:
        subprocess.run(["powershell", "-Command", ps_script], check=True)
        print(f"[!] SUCCESS: Evil Twin '{ssid}' should now be detectable by isItSafe.")
        print("[*] Keep this script running for the scanner to detect it.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping simulation...")
        subprocess.run(["powershell", "-Command", "netsh wlan stop hostednetwork"], capture_output=True)
    except Exception as e:
        print(f"[ERROR] Failed to start simulation: {e}")

if __name__ == "__main__":
    print("=== isItSAFE Evil Twin Simulator ===")
    target_ssid = input("Enter the SSID to clone for testing: ")
    if not target_ssid:
        target_ssid = "isItSafe_Test_Clone"
    
    create_fake_wifi(target_ssid)
