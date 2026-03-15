#!/usr/bin/env python3
"""
ShellX USB Device Auto-Deployment Daemon
Cross-platform Python implementation with auto-download capabilities
"""

import os
import sys
import time
import subprocess
import re
import hashlib
import signal
import logging
import argparse
import atexit
import shutil
import zipfile
import platform
from pathlib import Path
from datetime import datetime, timedelta
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ==============================================================================
# Configuration
# ==============================================================================

SCRIPT_VERSION = "1.0.0"
PROJECT_NAME = "ShellX"

# Get installation directory
if os.name == 'nt':  # Windows
    INSTALL_DIR = Path(os.environ.get('USERPROFILE', '~')) / '.shellx'
    BIN_DIR = INSTALL_DIR / 'bin'
else:  # Unix-like
    INSTALL_DIR = Path.home() / '.shellx'
    BIN_DIR = INSTALL_DIR / 'bin'

VERSION_FILE = INSTALL_DIR / '.shellx.version'
APK_FILE = INSTALL_DIR / 'shellx.apk'
APK_URL = 'https://cdn.shellx.cc/shellx.apk'
PID_FILE = INSTALL_DIR / '.shellx.pid'
LOG_FILE = INSTALL_DIR / '.shellx.log'

# ADB Configuration
ADB_VERSION = os.environ.get('SHELLX_ADB_VERSION', '29.0.6')
HUAWEI_VERSIONS = ['29.0.6', '29.0.5', '29.0.4', '29.0.3', '29.0.2', '29.0.1', '29.0.0', '28.0.3']

# Determine platform-specific settings
system = platform.system().lower()
if system == 'windows':
    PLATFORM = 'windows'
    ADB_EXE = 'adb.exe'
    ADB_ZIP_NAME = f'platform-tools_r{ADB_VERSION}-windows.zip'
elif system == 'darwin':
    PLATFORM = 'darwin'
    ADB_EXE = 'adb'
    ADB_ZIP_NAME = f'platform-tools_r{ADB_VERSION}-darwin.zip'
else:  # Linux
    PLATFORM = 'linux'
    ADB_EXE = 'adb'
    ADB_ZIP_NAME = f'platform-tools_r{ADB_VERSION}-linux.zip'

# Global variables
daemon_running = True

# ==============================================================================
# Logging Functions
# ==============================================================================

def setup_logging(daemon_mode=False):
    """Configure logging"""
    # Ensure log directory exists
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)

    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    handlers = [
        logging.FileHandler(LOG_FILE, encoding='utf-8')
    ]
    if not daemon_mode:
        handlers.append(logging.StreamHandler())

    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=handlers
    )
    return logging.getLogger(__name__)

def log_info(msg):
    """Log info message"""
    logger = logging.getLogger(__name__)
    logger.info(msg)

def log_warning(msg):
    """Log warning message"""
    logger = logging.getLogger(__name__)
    logger.warning(msg)

def log_error(msg):
    """Log error message"""
    logger = logging.getLogger(__name__)
    logger.error(msg)

def log_success(msg):
    """Log success message"""
    logger = logging.getLogger(__name__)
    logger.info(f"[SUCCESS] {msg}")

# ==============================================================================
# Utility Functions
# ==============================================================================

def is_windows():
    """Return True if running on Windows"""
    return os.name == 'nt'

def is_huawei_version_available():
    """Check if ADB version is available on Huawei Cloud"""
    return ADB_VERSION in HUAWEI_VERSIONS

def format_size(bytes_size):
    """Format bytes to human readable size"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f} TB"

def download_file(url, dest_path, description="File"):
    """Download file with progress bar"""
    log_info(f"Downloading {description} from: {url}")

    try:
        # Create SSL context that doesn't verify certificate (for self-signed certs)
        import ssl
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urlopen(req, timeout=120, context=ssl_context) as response:
            total_size = response.getheader('Content-Length')
            if total_size:
                total_size = int(total_size)

            downloaded = 0
            chunk_size = 8192
            last_percent = -1
            start_time = time.time()

            with open(dest_path, 'wb') as f:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)

                    # Show progress
                    if total_size:
                        percent = int((downloaded / total_size) * 100)
                        # Update every 2% or every 100KB
                        if percent != last_percent and (percent % 2 == 0 or downloaded % (100 * 1024) < chunk_size):
                            elapsed = time.time() - start_time
                            speed = downloaded / elapsed if elapsed > 0 else 0
                            eta = (total_size - downloaded) / speed if speed > 0 else 0

                            # Progress bar
                            bar_width = 40
                            filled = int(bar_width * downloaded / total_size)
                            bar = '█' * filled + '░' * (bar_width - filled)

                            print(f"\r  [{bar}] {percent}% ({format_size(downloaded)}/{format_size(total_size)}) "
                                  f"@ {format_size(speed)}/s ETA: {int(eta)}s", end='', flush=True)
                            last_percent = percent

            print()  # New line after progress bar

        log_success(f"{description} downloaded successfully")

        # Show file size
        if dest_path.exists():
            file_size = dest_path.stat().st_size
            log_info(f"File size: {format_size(file_size)}")

        return True

    except (URLError, HTTPError) as e:
        print()  # New line after progress bar
        log_error(f"Failed to download {description}: {e}")
        return False
    except Exception as e:
        print()  # New line after progress bar
        log_error(f"Error downloading {description}: {e}")
        return False

def verify_zip_file(zip_path):
    """Verify if a file is a valid ZIP archive"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.testzip()
        return True
    except Exception:
        return False

# ==============================================================================
# ADB Installation
# ==============================================================================

def get_adb_path():
    """Get the path to ADB executable"""
    adb_path = BIN_DIR / ADB_EXE
    if adb_path.exists():
        return str(adb_path)

    # Check environment variable
    adb_env = os.environ.get('ADB_PATH')
    if adb_env and Path(adb_env).exists():
        return adb_env

    # Try to find in system PATH
    adb_which = shutil.which('adb')
    if adb_which:
        return adb_which

    return None

def install_adb():
    """Download and install ADB platform-tools if not available"""
    # First check if ADB is available (from get_adb_path logic)
    adb_path = get_adb_path()
    if adb_path:
        # Check if it's our installed version or system ADB
        local_adb = BIN_DIR / ADB_EXE
        if str(adb_path) == str(local_adb):
            log_info(f"[OK] ADB already exists at {local_adb}, skipping download")
        else:
            log_info(f"[OK] System ADB found at: {adb_path}")
            log_info(f"  Using system ADB, skipping download")
            log_info(f"  Note: To use bundled ADB, run: rm {local_adb} and restart")
        return True

    # ADB not found anywhere, need to install
    print()
    print("=" * 60)
    print("  Installing ADB Platform-Tools")
    print("=" * 60)
    print(f"  Version: {ADB_VERSION}")
    print(f"  Platform: {PLATFORM.title()}")
    print(f"  Target: {BIN_DIR}")
    print("=" * 60)
    print()

    # Create bin directory
    BIN_DIR.mkdir(parents=True, exist_ok=True)

    adb_zip = INSTALL_DIR / ADB_ZIP_NAME
    download_success = False

    # Try Huawei Cloud mirror first (if version available)
    if is_huawei_version_available():
        log_info("[CLOUD] Huawei Cloud mirror available for this version")
        log_info("[DOWN]  Attempting download from mirrors.huaweicloud.com...")
        huawei_url = f"https://mirrors.huaweicloud.com/android/repository/{ADB_ZIP_NAME}"

        if download_file(huawei_url, adb_zip, "ADB from Huawei Cloud"):
            if verify_zip_file(adb_zip):
                log_success("[OK] Downloaded from Huawei Cloud mirror")
                download_success = True
            else:
                log_warning("Downloaded file is corrupted, will retry from Google")
        else:
            log_warning("Failed to download from Huawei Cloud, will retry from Google")

    # Fallback to Google official source
    if not download_success:
        log_info("[DOWN]  Attempting download from dl.google.com...")
        google_url = f"https://dl.google.com/android/repository/{ADB_ZIP_NAME}"

        if not download_file(google_url, adb_zip, "ADB from Google"):
            log_error("[FAIL] Failed to download ADB from all sources")
            return False

    # Extract ADB
    print()
    log_info("[PKG] Extracting ADB archive...")

    try:
        extract_dir = INSTALL_DIR / 'platform-tools-temp'
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        extract_dir.mkdir()

        with zipfile.ZipFile(adb_zip, 'r') as zf:
            zf.extractall(extract_dir)
            file_count = len(zf.namelist())
            log_info(f"  Extracted {file_count} files")

        # Copy ADB to bin directory
        platform_tools_dir = extract_dir / 'platform-tools'
        if not platform_tools_dir.exists():
            platform_tools_dir = extract_dir

        log_info(f"[COPY] Copying files to {BIN_DIR}...")

        copied_count = 0
        for item in platform_tools_dir.iterdir():
            dest = BIN_DIR / item.name
            if item.is_dir():
                shutil.copytree(item, dest, dirs_exist_ok=True)
                copied_count += len(list(dest.rglob('*')))
            else:
                shutil.copy2(item, dest)
                copied_count += 1

        # Make ADB executable on Unix
        if not is_windows():
            os.chmod(adb_path, 0o755)
            log_info("  Set executable permission on ADB")

        # Cleanup
        shutil.rmtree(extract_dir)
        adb_zip.unlink()
        log_info("  Cleaned up temporary files")

        print()
        log_success(f"[OK] ADB installed successfully to {BIN_DIR}")
        log_info(f"  Executable: {adb_path}")
        return True

    except Exception as e:
        print()
        log_error(f"[FAIL] Failed to extract ADB: {e}")
        return False

# ==============================================================================
# APK Download
# ==============================================================================

def install_apk():
    """Download APK if not exists"""
    if APK_FILE.exists():
        file_size = APK_FILE.stat().st_size
        log_info(f"[OK] APK already exists: {APK_FILE} ({format_size(file_size)})")
        return True

    print()
    print("=" * 60)
    print("  Downloading ShellX APK")
    print("=" * 60)
    print(f"  URL: {APK_URL}")
    print(f"  Target: {APK_FILE}")
    print("=" * 60)
    print()

    INSTALL_DIR.mkdir(parents=True, exist_ok=True)

    if download_file(APK_URL, APK_FILE, "ShellX APK"):
        print()
        log_success(f"[OK] APK downloaded successfully")
        return True
    else:
        print()
        log_error("[FAIL] Failed to download APK")
        return False

# ==============================================================================
# Version Management
# ==============================================================================

def create_version_file():
    """Create version file"""
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    with open(VERSION_FILE, 'w') as f:
        f.write(SCRIPT_VERSION)

def get_installed_version():
    """Get installed version"""
    if VERSION_FILE.exists():
        with open(VERSION_FILE, 'r') as f:
            return f.read().strip()
    return None

def add_to_path():
    """Add installation directory to PATH (for current session and future)"""
    install_str = str(INSTALL_DIR)

    # For current session
    current_path = os.environ.get('PATH', '')
    if install_str not in current_path:
        os.environ['PATH'] = f"{install_str}{os.pathsep}{current_path}"

    # For future sessions (persistent)
    if is_windows():
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment', 0, winreg.KEY_READ)
            path_value, _ = winreg.QueryValueEx(key, 'Path')
            winreg.CloseKey(key)

            if install_str not in path_value:
                new_path = f"{path_value};{install_str}"
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment', 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, 'Path', 0, winreg.REG_EXPAND_SZ, new_path)
                winreg.CloseKey(key)
                log_info("Added to user PATH (requires restart)")
        except Exception as e:
            log_warning(f"Could not update PATH: {e}")
    else:
        # Add to shell config
        shell_configs = [
            Path.home() / '.bashrc',
            Path.home() / '.zshrc',
            Path.home() / '.profile',
        ]

        path_export = f'\n# ShellX\nexport PATH="$PATH:{install_str}"\n'

        for config_file in shell_configs:
            if config_file.exists():
                content = config_file.read_text()
                if install_str not in content and 'ShellX' not in content:
                    with open(config_file, 'a') as f:
                        f.write(path_export)
                    log_info(f"Added PATH to {config_file.name}")
                    break

# ==============================================================================
# PID File Management
# ==============================================================================

def write_pid():
    """Write PID file"""
    try:
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
    except Exception as e:
        log_error(f"Error writing PID file: {e}")
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
        log_info(f"Found existing instance running (PID: {pid}), terminating...")
        try:
            if is_windows():
                subprocess.run(['taskkill', '/F', '/PID', str(pid)],
                               capture_output=True, check=False)
            else:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.5)
                if is_process_running(pid):
                    os.kill(pid, signal.SIGKILL)
            log_info(f"Successfully terminated old instance (PID: {pid})")
        except Exception as e:
            log_warning(f"Failed to terminate old instance: {e}")
        time.sleep(1)

def cleanup_pid():
    """Remove PID file"""
    try:
        if PID_FILE.exists():
            PID_FILE.unlink()
    except Exception:
        pass

# ==============================================================================
# Signal Handling
# ==============================================================================

def signal_handler(signum, frame):
    """Signal handler callback"""
    global daemon_running
    log_info(f"Received signal {signum}, exiting...")
    daemon_running = False

# ==============================================================================
# ADB Command Execution
# ==============================================================================

def run_adb_command(args):
    """Run ADB command and return output"""
    adb_path = get_adb_path()
    if not adb_path:
        log_error("ADB not found")
        return None

    cmd = [adb_path] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.stdout.strip()
    except Exception as e:
        log_error(f"Error executing ADB command: {e}")
        return None

def get_connected_devices():
    """Get list of connected devices"""
    output = run_adb_command(['devices'])
    if not output:
        return []

    devices = []
    for line in output.split('\n')[1:]:  # Skip header
        line = line.strip()
        if line and 'List of devices' not in line:
            parts = line.split()
            if parts and parts[0]:
                # Check if device is in valid state
                if len(parts) > 1 and parts[1] in ['device', 'offline', 'unauthorized', 'recovery']:
                    devices.append(parts[0])
    return devices

# ==============================================================================
# Device Version Management
# ==============================================================================

def get_device_deploy_version(device_id):
    """Get the deployed version from device"""
    version_file = '/data/local/tmp/shellx_files/deploy_version.txt'

    # Check if directory exists
    check_dir = run_adb_command(['-s', device_id, 'shell', 'test', '-d', '/data/local/tmp/shellx_files', '&&', 'echo', 'exists'])
    if not check_dir or 'exists' not in check_dir:
        return None

    # Read version file
    output = run_adb_command(['-s', device_id, 'shell', 'cat', version_file])
    if output:
        version = output.strip()
        if version and version != 'No such file or directory':
            return version
    return None

def write_device_deploy_version(device_id):
    """Write the current script version to device"""
    version_file = '/data/local/tmp/shellx_files/deploy_version.txt'

    # Create directory if not exists
    run_adb_command(['-s', device_id, 'shell', 'mkdir', '-p', '/data/local/tmp/shellx_files'])

    # Write version to file
    result = run_adb_command(['-s', device_id, 'shell', 'echo', f'"{SCRIPT_VERSION}"', '>', version_file])
    return result is not None

def check_device_version_update(device_id, daemon_mode=False):
    """Check if device version needs update and prompt user if needed"""
    deployed_version = get_device_deploy_version(device_id)

    if deployed_version is None:
        # First time deployment
        log_info(f"  First time deployment to device {device_id}")
        return True

    if deployed_version == SCRIPT_VERSION:
        log_info(f"  Device version: {deployed_version} (up to date)")
        return True

    # Version mismatch
    log_warning(f"  Version mismatch detected!")
    log_info(f"    Deployed version: {deployed_version}")
    log_info(f"    Current version:  {SCRIPT_VERSION}")

    if daemon_mode:
        # In daemon mode, auto-update without prompt
        log_info(f"  Auto-updating in daemon mode")
        return True

    # In foreground mode, prompt user
    print()
    print(f"WARNING: Device {device_id} has version {deployed_version}, but current script is {SCRIPT_VERSION}")
    print(f"  Do you want to update the device? (Y/n): ", end='', flush=True)

    try:
        import sys
        # Skip TTY check for Windows executables (PyInstaller compatibility)
        response = input().strip().lower()
        if response in ['', 'y', 'yes']:
            log_info(f"  User confirmed update")
            return True
        else:
            log_warning(f"  User declined update, skipping device {device_id}")
            return False
    except (EOFError, KeyboardInterrupt):
        log_warning(f"  Input interrupted, skipping device {device_id}")
        return False
    except Exception:
        # No interactive terminal available, skip update
        log_warning(f"  No interactive terminal, skipping device {device_id}")
        return False

# ==============================================================================
# Device Processing Functions
# ==============================================================================

def check_apk_installed(device_id):
    """Check if APK is already installed on device"""
    output = run_adb_command(['-s', device_id, 'shell', 'pm', 'list', 'packages', 'com.toscl.shellx'])
    if output and 'com.toscl.shellx' in output:
        return True
    return False

def show_service_menu(device_id, daemon_mode=False, apk_installed=True):
    """Show service management menu

    Args:
        device_id: The device identifier
        daemon_mode: If True, auto-select options without user interaction
        apk_installed: If True, APK is installed; if False, APK is not installed
    """
    print()
    print("=" * 60)
    print("  ShellX Service Menu")
    print("=" * 60)
    print(f"  Device: {device_id}")
    if apk_installed:
        print("  Status: APK already installed")
    else:
        print("  Status: APK not installed")
    print("=" * 60)
    print()
    print("  Please select an action:")
    if apk_installed:
        print("    1. Start service")
        print("    2. Stop service")
        print("    3. Reinstall service (Uninstall & Install)")
        print("    4. Uninstall service")
    else:
        print("    1. Install service")
        print("    2. Reconnect to check if device is ready")
    print("    0. Skip this device")
    print()
    if apk_installed:
        print("  Your choice [0-4]: ", end='', flush=True)
    else:
        print("  Your choice [0-2]: ", end='', flush=True)

    if daemon_mode:
        # In daemon mode, auto-select option based on APK status
        if apk_installed:
            log_info("  Daemon mode: Auto-selecting 'Start service'")
            print("1")
            return 1
        else:
            log_info("  Daemon mode: Auto-selecting 'Install service'")
            print("1")
            return 1

    try:
        import sys
        # Skip TTY check for Windows executables (PyInstaller compatibility)
        # Try to read input directly, handle all exceptions
        while True:
            try:
                choice = input().strip()
                # Validate input based on APK status
                valid_choices = ['0', '1', '2', '3', '4'] if apk_installed else ['0', '1', '2']
                if choice in valid_choices:
                    return int(choice)
                range_hint = "0-4" if apk_installed else "0-2"
                print(f"  Invalid choice. Please enter {range_hint}: ", end='', flush=True)
            except ValueError:
                print("  Invalid input. Please enter a number: ", end='', flush=True)
    except (EOFError, KeyboardInterrupt):
        log_warning("  Input interrupted, skipping device")
        print()
        return 0
    except Exception as e:
        # Any other error means no interactive terminal available
        log_warning("  No interactive terminal available, skipping device")
        print()
        return 0

def run_service_menu_loop(device_id, daemon_mode=False, apk_already_installed=True, initial_devices=None):
    """Run service menu loop for a device - return to menu after each action

    Args:
        device_id: The device identifier
        daemon_mode: If True, auto-select options without user interaction
        apk_already_installed: If True, APK is already installed; if False, just finished installing
        initial_devices: Initial set of connected devices to detect new connections

    Returns:
        True if should continue with normal flow (MainActivity, port forwarding, etc.)
        False if should exit menu loop (skip, device disconnected, new device connected, etc.)
    """
    while True:
        # Check if device is still connected before showing menu
        current_devices = set(get_connected_devices())
        if device_id not in current_devices:
            log_warning(f"  Device {device_id} disconnected, exiting menu")
            return False

        # Check if new device connected (device count increased)
        if initial_devices and len(current_devices) > len(initial_devices):
            new_devices = current_devices - set(initial_devices)
            if new_devices:
                log_info(f"  New device(s) detected: {', '.join(new_devices)}")
                log_info(f"  Exiting menu to process new device(s)")
                return False

        # Check current APK status
        apk_installed = check_apk_installed(device_id)

        # Show menu with current APK status
        choice = show_service_menu(device_id, daemon_mode=daemon_mode, apk_installed=apk_installed)

        # Execute the choice based on APK status
        if apk_installed:
            # APK is installed - handle different options
            if choice == 0:
                # Skip device - exit menu loop
                return False
            elif choice == 1:
                # Start service - continue with normal flow
                result = execute_service_choice(device_id, choice)
                if result:
                    return True  # Continue to MainActivity, port forwarding, etc.
                else:
                    continue  # Should not happen, but return to menu
            elif choice == 2:
                # Stop service - return to menu
                execute_service_choice(device_id, choice)
                continue
            elif choice == 3:
                # Reinstall service - complete flow (uninstall + install + startup)
                log_info(f"  Reinstalling service on device {device_id}...")

                # Step 1: Uninstall (stop + uninstall APK)
                log_info("  Step 1/2: Uninstalling old service...")
                stop_shell_script_on_device(device_id)
                if not uninstall_apk_from_device(device_id):
                    log_error("  Failed to uninstall old APK")
                    continue

                # Step 2: Complete installation and startup flow
                log_info("  Step 2/2: Installing and starting new service...")

                # Install APK
                if not install_apk_to_device(device_id):
                    log_error("  Installation failed, returning to menu...")
                    continue

                # Start MainActivity
                if not start_main_activity(device_id):
                    log_error("  Failed to start MainActivity, returning to menu...")
                    continue

                # Setup port forwarding
                if not setup_port_forwarding(device_id):
                    log_error("  Failed to setup port forwarding, returning to menu...")
                    continue

                # Execute shell script
                url = execute_shell_script(device_id)
                if not url:
                    log_error("  Failed to execute shell script, returning to menu...")
                    continue

                # Health check
                if not check_health_status():
                    log_error("  Health check failed, returning to menu...")
                    continue

                # Write deployment version
                if write_device_deploy_version(device_id):
                    log_info(f"[NOTE] Deployment version {SCRIPT_VERSION} recorded on device")

                # Open browser
                print()
                print("=" * 60)
                open_browser(url, enable_browser=True)
                print()
                log_success(f"[OK] Service reinstallation and startup completed!")
                print("=" * 60)
                print()

                # Return to menu after successful reinstallation
                log_info("Returning to menu...")
                continue
            elif choice == 4:
                # Uninstall service - return to menu (not exit!)
                execute_service_choice(device_id, choice)
                continue
        else:
            # APK is not installed - handle install/reconnect options
            if choice == 0:
                # Skip device - exit menu loop
                return False
            elif choice == 1:
                # Install service - full installation and startup flow
                log_info(f"  Installing and starting service on device {device_id}...")

                # Install APK
                if not install_apk_to_device(device_id):
                    log_error("  Installation failed, returning to menu...")
                    continue

                # Start MainActivity
                if not start_main_activity(device_id):
                    log_error("  Failed to start MainActivity, returning to menu...")
                    continue

                # Setup port forwarding
                if not setup_port_forwarding(device_id):
                    log_error("  Failed to setup port forwarding, returning to menu...")
                    continue

                # Execute shell script
                url = execute_shell_script(device_id)
                if not url:
                    log_error("  Failed to execute shell script, returning to menu...")
                    continue

                # Health check
                if not check_health_status():
                    log_error("  Health check failed, returning to menu...")
                    continue

                # Write deployment version
                if write_device_deploy_version(device_id):
                    log_info(f"[NOTE] Deployment version {SCRIPT_VERSION} recorded on device")

                # Open browser
                print()
                print("=" * 60)
                open_browser(url, enable_browser=True)
                print()
                log_success(f"[OK] Service installation and startup completed!")
                print("=" * 60)
                print()

                # Return to menu after successful installation
                log_info("Returning to menu...")
                continue
            elif choice == 2:
                # Reconnect / check device readiness
                log_info("  Refreshing device connection status...")
                continue

        return False

def execute_service_choice(device_id, choice):
    """Execute the selected service action"""
    actions = {
        0: "skip_device",
        1: "start",
        2: "stop",
        3: "reinstall",
        4: "uninstall"
    }

    action = actions.get(choice, "skip_device")
    log_info(f"  User selected: {choice} - {action}")

    if choice == 0:
        # Skip device
        log_info(f"  Skipping device {device_id} as requested")
        return False  # Don't process this device

    elif choice == 1:
        # Start service - continue with normal flow
        log_info(f"  Starting service on device {device_id}...")
        log_info(f"  Continuing with service startup flow...")
        return True

    elif choice == 2:
        # Stop service - return to menu
        log_info(f"  Stopping service on device {device_id}...")
        stop_shell_script_on_device(device_id)
        log_success(f"  Service stopped")
        return False  # Signal to return to menu (not exit)

    elif choice == 3:
        # Reinstall service (not used in menu loop, but kept for compatibility)
        log_info(f"  Reinstalling service on device {device_id}...")
        if not uninstall_apk_from_device(device_id):
            log_error(f"  Failed to uninstall old APK")
            return False
        if not install_apk_to_device(device_id):
            log_error(f"  Failed to install new APK")
            return False
        # Reinstall successful - will continue with normal flow
        log_success("  Reinstall completed successfully")
        return True

    elif choice == 4:
        # Uninstall service - exit menu loop
        log_info(f"  Uninstalling service from device {device_id}...")
        stop_shell_script_on_device(device_id)
        if uninstall_apk_from_device(device_id):
            log_success(f"  Service uninstalled")
        return False  # Exit menu loop

    return False

def install_apk_to_device(device_id):
    """Install APK to device"""
    log_info(f"[APK] [1/5] Installing APK to device {device_id}...")
    output = run_adb_command(['-s', device_id, 'install', '-r', str(APK_FILE)])
    if output and 'Success' in output:
        log_success(f"[OK] APK installed on device {device_id}")
        return True
    else:
        log_error(f"[FAIL] Failed to install APK on device {device_id}")
        if output:
            log_error(f"  Output: {output}")
        return False

def uninstall_apk_from_device(device_id):
    """Uninstall APK from device"""
    log_info(f"[DEL]  Uninstalling APK from device {device_id}...")
    output = run_adb_command(['-s', device_id, 'uninstall', 'com.toscl.shellx'])
    if output and 'Success' in output:
        log_success(f"[OK] APK uninstalled from device {device_id}")
        return True
    return False

def start_main_activity(device_id):
    """Start MainActivity on device"""
    log_info(f"[START] [2/5] Starting MainActivity on device {device_id}...")
    run_adb_command(['-s', device_id, 'shell', 'am', 'start',
                     '-n', 'com.toscl.shellx/.MainActivity'])
    log_info("  Waiting 6 seconds for MainActivity to initialize...")
    for i in range(6):
        time.sleep(1)
        print(f"  {i+1}/6 seconds...", end='\r')
    print("                    ")  # Clear the line
    log_success(f"[OK] MainActivity started")
    return True

def setup_port_forwarding(device_id):
    """Setup port forwarding for device"""
    log_info(f"[LINK] [3/5] Setting up port forwarding for device {device_id}...")

    # Define ports to forward
    port_mappings = [
        ('9091', '9091'),  # Main service port
        ('18789', '18789'),  # Additional port 1
        ('18788', '18788'),  # Additional port 2
    ]

    all_success = True
    for local_port, device_port in port_mappings:
        output = run_adb_command(['-s', device_id, 'forward', f'tcp:{local_port}', f'tcp:{device_port}'])
        if output is not None:
            log_info(f"  [OK] Port forwarding configured: localhost:{local_port} → device:{device_port}")
        else:
            log_error(f"  [FAIL] Failed to setup port forwarding for localhost:{local_port}")
            all_success = False

    if all_success:
        log_success("[OK] All port forwarding configured successfully")
        return True
    else:
        log_error(f"[FAIL] Some port forwarding failed for device {device_id}")
        return False

def execute_shell_script(device_id):
    """Execute shell script and extract URL"""
    log_info(f"[SCRIPT] [4/5] Executing shell script on device {device_id}...")
    log_info("  Waiting 3 seconds for service to be ready...")
    time.sleep(3)

    output = run_adb_command(['-s', device_id, 'shell', 'sh',
                              '/sdcard/Android/data/com.toscl.shellx/shellx.sh'])

    if output:
        log_info(f"  Shell output: {output.strip()}")

        # Extract URL using string splitting
        for part in output.split():
            if part.startswith('http://') or part.startswith('https://'):
                log_success(f"[OK] Extracted URL: {part}")
                return part

        # Try using -> as delimiter
        if '->' in output:
            after_arrow = output.split('->', 1)[1]
            for part in after_arrow.split():
                if part.startswith('http://') or part.startswith('https://'):
                    log_success(f"[OK] Extracted URL: {part}")
                    return part

    log_warning("[FAIL] No URL found in shell script output")
    return None

def stop_shell_script_on_device(device_id):
    """Stop shell script on device"""
    log_info(f"[STOP] Stopping shell script on device {device_id}...")
    run_adb_command(['-s', device_id, 'shell', 'sh',
                     '/sdcard/Android/data/com.toscl.shellx/shellx.sh',
                     '--stop'])

def check_health_status():
    """Check health status via HTTP"""
    log_info(f"[HEALTH] [5/5] Checking health status...")

    start_time = time.time()
    timeout = 15  # Increased from 5 to 15 seconds
    attempts = 0
    last_error = None

    while time.time() - start_time < timeout:
        attempts += 1
        try:
            req = Request('http://127.0.0.1:9091/api/health')
            with urlopen(req, timeout=2) as response:  # timeout goes here, not in Request
                if response.status == 200:
                    data = response.read().decode('utf-8')
                    # Simple check for healthy status
                    if 'healthy' in data.lower() or '"status"' in data:
                        elapsed = time.time() - start_time
                        log_success(f"[OK] Health check passed (attempt {attempts}, {elapsed:.1f}s)")
                        return True
                    else:
                        log_info(f"  Response: {data[:100]}")
        except Exception as e:
            last_error = str(e)
            if attempts == 1:
                log_info(f"  Waiting for service to be ready...")

        time.sleep(0.5)

    elapsed = time.time() - start_time
    log_error(f"[FAIL] Health check timed out after {timeout:.0f}s ({attempts} attempts)")
    if last_error:
        log_info(f"  Last error: {last_error}")
    return False

def open_browser(url, enable_browser=True):
    """Open URL in browser"""
    if url and enable_browser:
        log_info(f"[WEB] Opening browser: {url}")
        time.sleep(3)
        try:
            import webbrowser
            webbrowser.open(url)
            log_success("[OK] Browser opened")
        except Exception as e:
            log_warning(f"[!] Failed to open browser: {e}")
    elif url:
        log_info(f"[COPY] URL (browser disabled): {url}")

# ==============================================================================
# Daemon Process
# ==============================================================================

def daemonize():
    """Daemonize this process (Unix only)"""
    if is_windows():
        return

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        log_error(f"Fork #1 failed: {e}")
        sys.exit(1)

    os.setsid()

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        log_error(f"Fork #2 failed: {e}")
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

def run_daemon(enable_browser=True, daemon_mode=False):
    """Main daemon loop"""
    global daemon_running

    logger = logging.getLogger(__name__)
    logger.info("ShellX daemon started")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    atexit.register(cleanup_pid)

    print()
    log_info(f"[Phone] Using ADB: {get_adb_path()}")
    log_info("[WAIT] Waiting for USB devices to connect...")
    print()

    last_devices = set()
    failed_devices = {}  # device_id: retry_time
    checked_devices = set()  # Track devices that were version-checked
    processed_devices = set()  # Track devices that were successfully processed (to skip menu on reconnect)

    while daemon_running:
        try:
            current_devices = set(get_connected_devices())

            # Detect new devices
            new_devices = current_devices - last_devices
            disconnected_devices = last_devices - current_devices

            # Log device connection/disconnection
            if new_devices:
                for device_id in new_devices:
                    print()
                    log_success(f"[LINK] Device connected: {device_id}")
                    print("=" * 60)

            if disconnected_devices:
                for device_id in disconnected_devices:
                    log_warning(f"[LINK] Device disconnected: {device_id}")
                    # Remove from processed_devices so reconnect shows menu again
                    processed_devices.discard(device_id)

            devices_to_process = (current_devices - last_devices) | {
                device_id for device_id, retry_time in failed_devices.items()
                if datetime.now() >= retry_time and device_id in current_devices
            }

            for device_id in devices_to_process:
                # Check if this is a retry
                is_retry = device_id in failed_devices
                if is_retry:
                    print()
                    log_warning(f"[RETRY] Retrying device: {device_id}")
                    print("=" * 60)
                else:
                    log_info(f"[Phone] Processing device: {device_id}")
                    print("=" * 60)

                # Check version for new devices (not retries)
                if not is_retry and device_id not in checked_devices:
                    log_info(f"[SEARCH] Checking deployment version...")
                    if not check_device_version_update(device_id, daemon_mode=daemon_mode):
                        log_info(f"  Skipping device {device_id}")
                        checked_devices.add(device_id)  # Mark as checked so we don't prompt again
                        continue
                    checked_devices.add(device_id)

                # Check if APK is already installed
                apk_installed = check_apk_installed(device_id)

                # If APK is already installed and device not processed yet, enter menu loop
                if not is_retry and apk_installed and device_id not in processed_devices:
                    # Run service menu loop - user can perform multiple actions
                    # Pass current devices to detect new device connections
                    continue_flow = run_service_menu_loop(device_id, daemon_mode=daemon_mode, apk_already_installed=True, initial_devices=current_devices)

                    if not continue_flow:
                        # User chose to skip (0), uninstall (4), device disconnected, or new device connected
                        failed_devices.pop(device_id, None)
                        continue

                    # User chose option 1 (reinstall) or option 2 (start service) - continue with flow

                # Install APK if needed
                if not is_retry and not apk_installed:
                    if not install_apk_to_device(device_id):
                        failed_devices[device_id] = datetime.now() + timedelta(seconds=10)
                        log_error(f"[FAIL] Will retry in 10 seconds")
                        continue
                elif is_retry:
                    # For retry attempts, always try to install
                    if not install_apk_to_device(device_id):
                        failed_devices[device_id] = datetime.now() + timedelta(seconds=10)
                        log_error(f"[FAIL] Will retry in 10 seconds")
                        continue

                # Start MainActivity
                if not start_main_activity(device_id):
                    failed_devices[device_id] = datetime.now() + timedelta(seconds=10)
                    log_error(f"[FAIL] Will retry in 10 seconds")
                    continue

                # Setup port forwarding
                if not setup_port_forwarding(device_id):
                    failed_devices[device_id] = datetime.now() + timedelta(seconds=10)
                    log_error(f"[FAIL] Will retry in 10 seconds")
                    continue

                # Execute shell script
                url = execute_shell_script(device_id)
                if not url:
                    failed_devices[device_id] = datetime.now() + timedelta(seconds=10)
                    log_error(f"[FAIL] Will retry in 10 seconds")
                    continue

                # Health check
                if not check_health_status():
                    log_warning(f"[!] Health check failed for device {device_id}")
                    log_info("[DEL]  Uninstalling APK and will retry in 10 seconds...")
                    stop_shell_script_on_device(device_id)
                    uninstall_apk_from_device(device_id)
                    failed_devices[device_id] = datetime.now() + timedelta(seconds=10)
                    continue

                # Write deployment version to device
                if write_device_deploy_version(device_id):
                    log_info(f"[NOTE] Deployment version {SCRIPT_VERSION} recorded on device")
                else:
                    log_warning(f"[!] Failed to write deployment version to device")

                # Open browser
                print()
                print("=" * 60)
                open_browser(url, enable_browser=enable_browser)
                failed_devices.pop(device_id, None)
                print()
                log_success(f"[OK] Device {device_id} processing complete!")
                print("=" * 60)
                print()

                # After successful installation/startup, enter service menu loop
                # This allows user to perform additional actions on the same device
                if not daemon_mode:
                    log_info("Entering service menu for additional actions...")
                    # Pass current devices to detect new device connections
                    run_service_menu_loop(device_id, daemon_mode=False, apk_already_installed=True, initial_devices=current_devices)

                # Mark as processed to avoid re-processing on reconnect
                processed_devices.add(device_id)

            last_devices = current_devices
            time.sleep(1)

        except Exception as e:
            logger.error(f"Error: {e}")
            time.sleep(1)

    logger.info("Daemon exiting")
    cleanup_pid()

# ==============================================================================
# Main Entry Point
# ==============================================================================

def show_status():
    """Show daemon status"""
    pid = read_pid()
    if pid and is_process_running(pid):
        print(f"Daemon is running (PID: {pid})")
        if LOG_FILE.exists():
            print("\nRecent log entries (last 10 lines):")
            try:
                with open(LOG_FILE, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for line in lines[-10:]:
                        print(line.rstrip())
            except Exception as e:
                print(f"Failed to read log: {e}")
    else:
        print("Daemon is not running")

def stop_daemon():
    """Stop daemon"""
    pid = read_pid()
    if pid and is_process_running(pid):
        print(f"Stopping daemon (PID: {pid})...")
        kill_existing_instance()
        cleanup_pid()
        print("Daemon stopped")
    else:
        print("Daemon is not running")

def stop_shellx_on_devices():
    """Stop ShellX on all connected devices"""
    print("Stopping ShellX on all devices...")
    devices = get_connected_devices()
    for device_id in devices:
        stop_shell_script_on_device(device_id)
    print(f"Stopped on {len(devices)} device(s)")

def main():
    # Fix Windows encoding issue for emoji and special characters
    if sys.platform == 'win32':
        import io
        try:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
        except Exception:
            pass  # Fallback to default encoding if wrapper fails

    parser = argparse.ArgumentParser(
        description='ShellX USB Device Auto-Deployment Daemon',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py              # Run in foreground
  python main.py -d           # Run as daemon
  python main.py -s           # Show status
  python main.py -k           # Stop daemon
        """
    )

    parser.add_argument('-d', '--daemon', action='store_true',
                        help='Run as background daemon')
    parser.add_argument('-k', '--kill', action='store_true',
                        help='Stop running daemon')
    parser.add_argument('-s', '--status', action='store_true',
                        help='Show daemon status')
    parser.add_argument('--stop', action='store_true',
                        help='Stop ShellX on all devices')
    parser.add_argument('--no-browser', action='store_true',
                        help='Disable auto-open browser')

    args = parser.parse_args()

    print()
    print("=" * 60)
    print(f"    {PROJECT_NAME} v{SCRIPT_VERSION} - https://shellx.ai")
    print("    USB Device Auto-Deployment Daemon")
    print(f" [START]  Please ensure your Android device is connected & USB debugging Authorized  [START] ")
    print("=" * 60)
    print()

    # Handle --stop
    if args.stop:
        stop_shellx_on_devices()
        sys.exit(0)

    # Handle --status
    if args.status:
        show_status()
        sys.exit(0)

    # Handle --kill
    if args.kill:
        stop_daemon()
        sys.exit(0)

    # Setup logging for non-daemon mode
    if not args.daemon:
        setup_logging(daemon_mode=False)

    # Installation checks
#     log_info("[SEARCH] Checking requirements...")

    # Check Python version
#     if sys.version_info < (3, 6):
#         log_error("[FAIL] Python 3.6 or higher is required")
#         sys.exit(1)
#
#     py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
#     log_info(f"  Python version: {py_version}")
#     log_success("[OK] All requirements satisfied")
#     print()

    # Install ADB
    if not install_adb():
        log_error("[FAIL] ADB installation failed")
        sys.exit(1)

    # Download APK
    if not install_apk():
        log_error("[FAIL] APK download failed")
        sys.exit(1)

    # Create version file
    create_version_file()

    # Add to PATH
    add_to_path()

    # Kill existing instance
    kill_existing_instance()

    # Run daemon
    if args.daemon:
        log_info("[START] Starting ShellX daemon in background...")
        if not is_windows():
            daemonize()
        else:
            try:
                import ctypes
                kernel32 = ctypes.WinDLL('kernel32')
                user32 = ctypes.WinDLL('user32')
                hwnd = kernel32.GetConsoleWindow()
                if hwnd:
                    user32.ShowWindow(hwnd, 0)  # SW_HIDE
            except Exception:
                pass
        write_pid()
        setup_logging(daemon_mode=True)
    else:
        print()
        log_info("[START] Starting ShellX daemon in foreground...")
        print("  Press Ctrl+C to stop")
        print()
        write_pid()

    run_daemon(enable_browser=(not args.no_browser), daemon_mode=args.daemon)

if __name__ == "__main__":
    main()
