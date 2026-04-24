import getpass
import os
import re
from netmiko import ConnectHandler

# Specific Command Set for Layer 2 Forensics
l2_commands = [
    'show run',
    'show ip interface brief',
    'show vlan brief',
    'show interfaces trunk',
    'show interface status',
    'show spanning-tree summary',
    'show spanning-tree root',
    'show cdp neighbors',
    'show inventory',
    'show logging',
    'show vtp status'
]

LONG_TIMEOUT_CMDS = {'show run'}
LONG_READ_TIMEOUT = 90
DEFAULT_READ_TIMEOUT = 30

# Get credentials securely
username = input("Enter your SSH username: ")
password = getpass.getpass("Enter your SSH password: ")
enable_secret = getpass.getpass("Enter your Enable Secret (press Enter if same as password): ") or password

# Dedicated folder for L2 logs
script_dir = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(script_dir, "network_audit_L2_logs")
os.makedirs(log_dir, exist_ok=True)

# Uses a separate IP file for Layer 2 devices
l2_ips_file = os.path.join(script_dir, 'l2_ips.txt')
with open(l2_ips_file, 'r', encoding='utf-8') as f:
    device_ips = [line.strip() for line in f if line.strip()]

failed_devices = []

for ip in device_ips:
    try:
        print(f"Connecting to Layer 2 device: {ip}...")

        device = {
            'device_type': 'cisco_ios',
            'host': ip,
            'username': username,
            'password': password,
            'secret': enable_secret,
            'conn_timeout': 15,
            'read_timeout_override': DEFAULT_READ_TIMEOUT,
        }

        with ConnectHandler(**device) as net_connect:

            if not net_connect.check_enable_mode():
                print(f"  Entering enable mode on {ip}...")
                net_connect.enable()

            raw_prompt = net_connect.find_prompt()
            hostname = re.sub(r'[^\w.-]', '', raw_prompt)
            hostname = hostname or ip

            filename = os.path.join(log_dir, f"{hostname}_{ip}_L2_audit.txt")

            with open(filename, 'w', encoding='utf-8') as log_file:
                for cmd in l2_commands:
                    log_file.write(f"\n{'=' * 20} {cmd} {'=' * 20}\n")

                    read_timeout = LONG_READ_TIMEOUT if cmd in LONG_TIMEOUT_CMDS else DEFAULT_READ_TIMEOUT
                    output = net_connect.send_command(cmd, read_timeout=read_timeout)

                    log_file.write(output)
                    log_file.write("\n")

            print(f"  Done. Saved to {filename}")

    except Exception as e:
        print(f"  Failed to connect to {ip}: {e}")
        failed_devices.append((ip, str(e)))

if failed_devices:
    failure_log = os.path.join(log_dir, "failed_devices.txt")
    with open(failure_log, 'w', encoding='utf-8') as f:
        for ip, reason in failed_devices:
            f.write(f"{ip}: {reason}\n")
    print(f"\nLayer 2 audit complete. {len(failed_devices)} device(s) failed. See {failure_log}")
else:
    print("\nLayer 2 audit complete. All devices succeeded.")
