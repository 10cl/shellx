#!/usr/bin/env python3
import os
import time
import subprocess
import sys
import re
import webbrowser
import hashlib
import signal
import logging
import argparse
import atexit
import requests
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

# Global variables
PID_FILE = Path(".shellx.pid")
LOG_FILE = Path(".shellx.log")
daemon_running = True

def setup_logging():
    """Configure logging"""
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler(LOG_FILE, encoding='utf-8'),
            logging.StreamHandler() if not is_windows() else logging.NullHandler()
        ]
    )
    return logging.getLogger(__name__)

def is_windows():
    """Return True if running on Windows"""
    return os.name == 'nt'

def write_pid():
    """Write PID file"""
    try:
        PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
    except Exception as e:
        print(f"Error writing PID file: {e}")
        sys.exit(1)

def read_pid():
    """Read PID from file"""
    try:
        if PID_FILE.exists():
            with open(PID_FILE, 'r') as f:
                return int(f.read().strip())
    except Exception:
        pass
    return None

def is_process_running(pid):
    """Check if a process is running"""
    if is_windows():
        try:
            result = subprocess.run(['tasklist', '/FI', f'PID eq {pid}'],
                                   capture_output=True, text=True)
            return str(pid) in result.stdout
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

def kill_existing_instance():
    """Kill any existing running instance of the daemon"""
    pid = read_pid()
    if pid and is_process_running(pid):
        logger = logging.getLogger(__name__)
        logger.info(f"Found existing instance running (PID: {pid}), terminating...")
        try:
            if is_windows():
                subprocess.run(['taskkill', '/F', '/PID', str(pid)],
                               capture_output=True, check=False)
            else:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.5)
                if is_process_running(pid):
                    os.kill(pid, signal.SIGKILL)
            logger.info(f"Successfully terminated old instance (PID: {pid})")
        except Exception as e:
            logger.warning(f"Failed to terminate old instance: {e}")
        time.sleep(1)

def cleanup_pid():
    """Remove PID file"""
    try:
        if PID_FILE.exists():
            PID_FILE.unlink()
    except Exception:
        pass

def signal_handler(signum, frame):
    """Signal handler callback"""
    global daemon_running
    logger = logging.getLogger(__name__)
    logger.info(f"Received signal {signum}, exiting...")
    daemon_running = False

def daemonize():
    """Daemonize this process (Unix only)"""
    if is_windows():
        return

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        print(f"Fork #1 failed: {e}")
        sys.exit(1)

    os.setsid()

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        print(f"Fork #2 failed: {e}")
        sys.exit(1)

    sys.stdout.flush()
    sys.stderr.flush()

    si = open(os.devnull, 'r')
    so = open(os.devnull, 'a+')
    se = open(os.devnull, 'a+')

    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

    atexit.register(cleanup_pid)

def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating SHA-256 for {file_path}: {e}")
        return None

def verify_apk_integrity(apk_path):
    """Verify APK file integrity using SHA-256"""
    if not apk_path.exists():
        print(f"❌ APK file not found: {apk_path}")
        return False

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

    try:
        with open(sha256_file_path, 'r') as f:
            expected_hash = f.read().strip().split()[0]  # Handle format: "hash filename"
    except Exception as e:
        print(f"❌ Error reading SHA-256 file {sha256_file_path}: {e}")
        return False

    actual_hash = calculate_sha256(apk_path)
    if actual_hash is None:
        return False

    if actual_hash.lower() == expected_hash.lower():
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
        logger = logging.getLogger(__name__)
        logger.error(f"Error executing command: {command}")
        logger.error(f"Error: {e.stderr}")
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
    print("Waiting 6 seconds for MainActivity to initialize...")
    time.sleep(6)
    return True

def execute_shell_script(device_id):
    """Execute shell script and return the URL from the output"""
    print(f"Executing shell script on device {device_id}...")
    result = run_command(f"{ADB_CMD} -s {device_id} shell sh /sdcard/Android/data/com.toscl.shellx/shellx.sh --dex=/data/local/tmp/shellx_dex.dex")
    if result:
        print(f"Shell script execution result: {result}")
        url_match = re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', result)
        if url_match:
            return url_match.group(0)
    else:
        print(f"Failed to execute shell script on device {device_id}")
    return None

def check_health_status():
    """Check health status by accessing http://127.0.0.1:9091/api/health for 5 seconds"""
    print("Checking health status...")
    import time
    start_time = time.time()
    while time.time() - start_time < 5:
        try:
            response = requests.get("http://127.0.0.1:9091/api/health", timeout=1)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "healthy":
                    print("Health check passed")
                    return True
                else:
                    print(f"Health check failed: status = {data.get('status')}")
            else:
                print(f"Health check failed: HTTP {response.status_code}")
        except Exception as e:
            print(f"Health check failed: {e}")
        time.sleep(0.5)  # Wait 0.5 seconds before next check
    print("Health check timed out after 5 seconds")
    return False

def stop_shell_script(device_id):
    """Stop shell script on device"""
    print(f"Stopping shell script on device {device_id}...")
    result = run_command(f"{ADB_CMD} -s {device_id} shell sh /sdcard/Android/data/com.toscl.shellx/shellx.sh --stop --dex=/data/local/tmp/shellx_dex.dex")
    if result:
        print(f"Shell script stop result: {result}")
        return True
    else:
        print(f"Failed to stop shell script on device {device_id}")
        return False

def open_browser(url, enable_browser=True):
    time.sleep(3)
    """Open the URL in the default browser"""
    if url:
        if enable_browser:
            print(f"Opening URL in browser: {url}")
            webbrowser.open(url)
        else:
            print(f"URL to open (browser disabled): {url}")
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
    # Placeholder implementation; replace with actual APK analysis if needed.
    return 1

def process_device(device_id, apk_path):
    """Process installation/update logic for a single device"""
    print(f"Processing device: {device_id}")
    print(f"APK not installed on device {device_id}, installing new version")
    return install_apk(device_id, apk_path)

def run_daemon(enable_browser=True):
    """Main daemon process loop"""
    global daemon_running

    logger = setup_logging()
    logger.info("ShellX daemon started")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    atexit.register(cleanup_pid)

    apk_path = Path("shellx.apk")
    if not apk_path.exists():
        logger.error(f"APK not found at {apk_path}")
        sys.exit(1)

    if not verify_apk_integrity(apk_path):
        logger.error("❌ APK integrity check failed. Aborting deployment.")
        sys.exit(1)

    logger.info("Waiting for USB devices to connect...")
    last_devices = set()
    failed_devices = {}  # device_id: retry_time

    while daemon_running:
        try:
            current_devices = set(get_connected_devices())

            devices_to_process = (current_devices - last_devices) | {
                device_id for device_id, retry_time in failed_devices.items()
                if datetime.now() >= retry_time and device_id in current_devices
            }

            for device_id in devices_to_process:
                logger.info(f"Processing device: {device_id}")

                if process_device(device_id, apk_path):
                    if start_main_activity(device_id):
                        if setup_port_forwarding(device_id):
                            url = execute_shell_script(device_id)
                            if url:
                                if check_health_status():
                                    open_browser(url, enable_browser=enable_browser)
                                    failed_devices.pop(device_id, None)
                                else:
                                    logger.warning(f"Health check failed for device {device_id}. Uninstalling and retrying...")
                                    uninstall_apk(device_id)
                                    failed_devices[device_id] = datetime.now() + timedelta(seconds=5)  # Retry sooner
                                    continue  # Skip to next device
                            else:
                                failed_devices[device_id] = datetime.now() + timedelta(seconds=10)
                                logger.warning(f"Shell script execution failed for device {device_id}")
                        else:
                            failed_devices[device_id] = datetime.now() + timedelta(seconds=10)
                            logger.warning(f"Port forwarding setup failed for device {device_id}")
                    else:
                        failed_devices[device_id] = datetime.now() + timedelta(seconds=10)
                        logger.warning(f"Device {device_id} failed to start MainActivity. Will retry in 10 seconds.")
                else:
                    failed_devices[device_id] = datetime.now() + timedelta(seconds=10)
                    logger.warning(f"Device {device_id} installation failed. Will retry in 10 seconds.")

            last_devices = current_devices
            time.sleep(1)  # Check every second

        except Exception as e:
            logger.error(f"Error: {e}")
            time.sleep(1)

    logger.info("Daemon exiting")
    cleanup_pid()

def stop_shellx_process():
    """Stop ShellX process"""
    print("Stopping ShellX process...")
    try:
        # First, try to stop shellx processes on connected devices
        devices = get_connected_devices()
        device_stop_success = True
        for device_id in devices:
            if not stop_shell_script(device_id):
                device_stop_success = False
        return True
        # Then stop local shellx processes
        # local_stop_success = False
        # if is_windows():
        #     # On Windows, kill shellx.exe process
        #     result = subprocess.run(['taskkill', '/F', '/IM', 'shellx.exe'],
        #                            capture_output=True, text=True)
        #     local_stop_success = result.returncode == 0
        # else:
        #     # On Unix-like systems, kill shellx process
        #     result = subprocess.run(['pkill', '-f', 'shellx'],
        #                            capture_output=True, text=True)
        #     local_stop_success = result.returncode == 0

        # if device_stop_success or local_stop_success:
        #     print("Successfully stopped ShellX process(es)")
        #     return True
        # else:
        #     print("ShellX process may not be running")
        #     return False
    except Exception as e:
        print(f"Error stopping ShellX process: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='ShellX USB Device Auto-Deployment Daemon')
    parser.add_argument('-d', '--daemon', action='store_true', help='Run as background daemon process')
    parser.add_argument('-k', '--kill', action='store_true', help='Stop running daemon process')
    parser.add_argument('-s', '--status', action='store_true', help='Show daemon process status')
    parser.add_argument('--no-browser', action='store_true', help='Do not open browser when URL detected')
    parser.add_argument('--stop', action='store_true', help='Stop ShellX process')

    args = parser.parse_args()

    # Stop ShellX process
    if args.stop:
        success = stop_shellx_process()
        sys.exit(0 if success else 1)

    # Show status
    if args.status:
        pid = read_pid()
        if pid and is_process_running(pid):
            print(f"Daemon process is running (PID: {pid})")
            if LOG_FILE.exists():
                print(f"\nRecent log entries (last 10 lines):")
                try:
                    with open(LOG_FILE, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        for line in lines[-10:]:
                            print(line.rstrip())
                except Exception as e:
                    print(f"Failed to read log: {e}")
        else:
            print("Daemon is not running")
        sys.exit(0)

    # Stop daemon
    if args.kill:
        pid = read_pid()
        if pid and is_process_running(pid):
            print(f"Stopping daemon process (PID: {pid})...")
            kill_existing_instance()
            cleanup_pid()
            print("Daemon stopped")
        else:
            print("Daemon is not running")
        sys.exit(0)

    # Kill old instance if present
    kill_existing_instance()

    # Daemon mode
    if args.daemon:
        logger = logging.getLogger(__name__)

        if not is_windows():
            daemonize()
        else:
            import ctypes
            try:
                print("Hiding console window...")
                kernel32 = ctypes.WinDLL('kernel32')
                user32 = ctypes.WinDLL('user32')

                hwnd = kernel32.GetConsoleWindow()
                if hwnd:
                    user32.ShowWindow(hwnd, 0)  # SW_HIDE = 0
            except Exception:
                pass

        write_pid()

        run_daemon(enable_browser=(not args.no_browser))
    else:
        # Foreground mode, for debugging or interactive use
        write_pid()
        logger = setup_logging()

        try:
            run_daemon(enable_browser=(not args.no_browser))
        except KeyboardInterrupt:
            print("\nProgram interrupted by user")
            cleanup_pid()
            sys.exit(0)

if __name__ == "__main__":
    main()
