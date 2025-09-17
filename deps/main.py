#!/usr/bin/env python3
import os
import time
import subprocess
import sys
import re
import webbrowser
import hashlib
import argparse
from pathlib import Path
from datetime import datetime, timedelta

def get_adb_cmd():
    """
    Returns the correct adb command for the current platform.
    On Windows, use 'adb.exe' if available, otherwise 'adb'.
    On Unix, use './adb' if present, otherwise 'adb'.
    """
    # Check for environment variable override
    adb_env = os.environ.get("ADB_PATH")
    if adb_env:
        return adb_env

    if os.name == "nt":
        # Windows
        if Path("adb.exe").exists():
            return "adb.exe"
        elif Path("./adb.exe").exists():
            return "./adb.exe"
        else:
            return "adb"
    else:
        # Unix-like
        if Path("./adb").exists():
            return "./adb"
        else:
            return "adb"

ADB_CMD = get_adb_cmd()

def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read the file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating SHA-256 for {file_path}: {e}")
        return None

def verify_apk_integrity(apk_path):
    """Verify APK file integrity using SHA-256"""
    # print(f"🔍 Verifying APK integrity...")
    
    # Check if APK file exists
    if not apk_path.exists():
        print(f"❌ APK file not found: {apk_path}")
        return False
    
    # Look for SHA-256 file in multiple locations
    sha256_file_paths = [
        apk_path.parent / f"{apk_path.name}.sha256",
        apk_path.parent / "dist" / f"{apk_path.name}.sha256",
        apk_path.parent.parent / "dist" / f"{apk_path.name}.sha256"
    ]
    
    sha256_file_path = None
    for path in sha256_file_paths:
        if path.exists():
            sha256_file_path = path
            break
    
    if not sha256_file_path:
        print(f"⚠️ SHA-256 file not found. Skipping integrity check.")
        print(f"Expected locations:")
        for path in sha256_file_paths:
            print(f"  - {path}")
        return True  # Continue without verification
    
    # Read expected SHA-256 hash
    try:
        with open(sha256_file_path, 'r') as f:
            expected_hash = f.read().strip().split()[0]  # Handle format: "hash filename"
    except Exception as e:
        print(f"❌ Error reading SHA-256 file {sha256_file_path}: {e}")
        return False
    
    # Calculate actual SHA-256 hash
    actual_hash = calculate_sha256(apk_path)
    if actual_hash is None:
        return False
    
    # Compare hashes
    if actual_hash.lower() == expected_hash.lower():
        #print(f"✅ APK integrity verified successfully")
        #print(f"   Expected: {expected_hash}")
        #print(f"   Actual:   {actual_hash}")
        return True
    else:
        print(f"❌ APK integrity check failed!")
        print(f"   Expected: {expected_hash}")
        print(f"   Actual:   {actual_hash}")
        print(f"   File: {apk_path}")
        print(f"   SHA-256 file: {sha256_file_path}")
        return False

def run_command(command):
    """Run a command and return its output"""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {command}")
        print(f"Error: {e.stderr}")
        return None

def get_connected_devices():
    """Get the list of connected devices"""
    output = run_command(f"{ADB_CMD} devices")
    if not output:
        return []
    
    devices = []
    for line in output.split('\n')[1:]:  # Skip the first line "List of devices attached"
        if line.strip():
            device_id = line.split('\t')[0]
            if device_id != 'List of devices attached':
                devices.append(device_id)
    return devices

def uninstall_apk(device_id):
    """Uninstall the APK from the specified device"""
    print(f"Uninstalling APK from device {device_id}...")
    result = run_command(f"{ADB_CMD} -s {device_id} uninstall com.toscl.shellx")
    if result and "Success" in result:
        print(f"Successfully uninstalled APK from device {device_id}")
        return True
    else:
        print(f"Failed to uninstall APK from device {device_id}")
        return False

def setup_port_forwarding(device_id):
    """Set up port forwarding"""
    print(f"Setting up port forwarding for device {device_id}...")
    result = run_command(f"{ADB_CMD} -s {device_id} forward tcp:9091 tcp:9091")
    if result is not None:
        print(f"Successfully set up port forwarding for device {device_id}")
        return True
    else:
        print(f"Failed to set up port forwarding for device {device_id}")
        return False

def install_apk(device_id, apk_path):
    """Install the APK to the specified device"""
    print(f"Installing APK to device {device_id}...")
    result = run_command(f"{ADB_CMD} -s {device_id} install -r {apk_path}")
    if result and "Success" in result:
        print(f"Successfully installed APK on device {device_id}")
        return True
    else:
        print(f"Failed to install APK on device {device_id}")
        return False

def start_main_activity(device_id):
    """Start MainActivity"""
    print(f"Starting MainActivity on device {device_id}...")
    result = run_command(f"{ADB_CMD} -s {device_id} shell am start -n com.toscl.shellx/.MainActivity")
    # if result and "Success" in result:
    #     print(f"Successfully started MainActivity on device {device_id}")
    #     return True
    # else:
        # print(f"Failed to start MainActivity on device {device_id}")
        # return False
    print("Waiting 3 seconds for MainActivity to initialize...")
    time.sleep(3)
    return True

def execute_shell_script(device_id):
    """Execute shell script and return the URL from the output"""
    print(f"Executing shell script on device {device_id}...")
    result = run_command(f"{ADB_CMD} -s {device_id} shell sh /sdcard/Android/data/com.toscl.shellx/shellx.sh --dex=/data/local/tmp/shellx_dex.dex")
    if result:
        print(f"Shell script execution result: {result}")
        # Try to extract URL from output
        url_match = re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', result)
        if url_match:
            return url_match.group(0)
    else:
        print(f"Failed to execute shell script on device {device_id}")
    return None

def open_browser(url):
    time.sleep(3)
    """Open the URL in the default browser"""
    if url:
        print(f"Opening URL in browser: {url}")
        webbrowser.open(url)
    else:
        print("No URL found to open")

def get_installed_version(device_id):
    """Get the installed APK version on the device"""
    try:
        result = subprocess.run(
            [ADB_CMD, '-s', device_id, 'shell', 'dumpsys', 'package', 'com.toscl.shellx'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            # Find version code
            version_match = re.search(r'versionCode=(\d+)', result.stdout)
            if version_match:
                return int(version_match.group(1))
    except Exception as e:
        print(f"Error getting version for device {device_id}: {e}")
    return None

def is_apk_installed(device_id):
    """Check if the APK is installed on the device"""
    try:
        result = subprocess.run(
            [ADB_CMD, '-s', device_id, 'shell', 'pm', 'list', 'packages', 'com.toscl.shellx'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0 and 'com.toscl.shellx' in result.stdout
    except Exception as e:
        print(f"Error checking APK installation for device {device_id}: {e}")
        return False

def get_apk_version(apk_path):
    """Get the version code of the APK file"""
    # try:
    #     result = subprocess.run(
    #         ['aapt', 'dump', 'badging', apk_path],
    #         capture_output=True,
    #         text=True
    #     )
    #     if result.returncode == 0:
    #         version_match = re.search(r'versionCode=\'(\d+)\'', result.stdout)
    #         if version_match:
    #             return int(version_match.group(1))
    # except Exception as e:
    #     print(f"Error getting APK version: {e}")
    # return None
    return 1

def process_device(device_id, apk_path):
    """Process installation/update logic for a single device"""
    print(f"Processing device: {device_id}")

    # Get APK version
    # apk_version = get_apk_version(apk_path)
    # if apk_version is None:
    #     print(f"Error: Could not determine APK version for {apk_path}")
    #     return False

    # Check if APK is installed
    # if is_apk_installed(device_id):
    #     # Get installed version
    #     installed_version = get_installed_version(device_id)
    #     if installed_version is None:
    #         print(f"Error: Could not determine installed version on device {device_id}")
    #         return False
    #
    #     # Compare versions
    #     # if installed_version < apk_version:
    #         print(f"Updating from version {installed_version} to {apk_version}")
    #         if uninstall_apk(device_id):
    #             return install_apk(device_id, apk_path)
    #         return False
    #     # else:
    #     #     print(f"Device {device_id} already has the latest version ({installed_version})")
    #     #     return True
    # else:
    print(f"APK not installed on device {device_id}, installing new version")
    return install_apk(device_id, apk_path)

def main():
    parser = argparse.ArgumentParser(description='ShellX APK deployment script')
    parser.add_argument('--just-start', action='store_true', 
                       help='Only start the app if already installed, skip installation')
    args = parser.parse_args()
    apk_path = Path("shellx.apk")
    if not apk_path.exists():
        print(f"Error: APK not found at {apk_path}")
        sys.exit(1)

    # Verify APK integrity before proceeding
    if not verify_apk_integrity(apk_path):
        print("❌ APK integrity check failed. Aborting deployment.")
        sys.exit(1)

    print("Waiting for USB device connection...")
    last_devices = set()
    failed_devices = {}  # Record devices that failed installation and their retry time

    while True:
        try:
            current_devices = set(get_connected_devices())

            # Check for newly connected devices and devices that need retry
            devices_to_process = (current_devices - last_devices) | {
                device_id for device_id, retry_time in failed_devices.items()
                if datetime.now() >= retry_time and device_id in current_devices
            }

            for device_id in devices_to_process:
                print(f"Processing device: {device_id}")
                if args.just_start and is_apk_installed(device_id):
                    print(f"APK already installed on device {device_id}, starting directly")
                    execute_shell_script(device_id)
                else:
                    # Install new version
                    if process_device(device_id, apk_path):
                        # Start MainActivity
                        if start_main_activity(device_id):
                            if setup_port_forwarding(device_id):
                                url = execute_shell_script(device_id)
                                if url:
                                    open_browser(url)
                            # Remove device from failed list if present
                            failed_devices.pop(device_id, None)
                        else:
                            # If starting MainActivity fails, add to failed list
                            failed_devices[device_id] = datetime.now() + timedelta(seconds=10)
                            print(f"Device {device_id} failed to start MainActivity. Will retry in 10 seconds.")
                    else:
                        # Record or update failure time
                        failed_devices[device_id] = datetime.now() + timedelta(seconds=10)
                        print(f"Device {device_id} installation failed. Will retry in 10 seconds.")


            last_devices = current_devices
            time.sleep(1)  # Check every second

        except KeyboardInterrupt:
            print("\nDeployment stopped by user")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()
