import getpass
import os
import re
from netmiko import ConnectHandler

# Define the list of commands for the audit
commands = [
    'show run',
    'show ip interface brief',
    'show ip eigrp neighbors detail',
    'show ip protocols',
    'show ip route',
    'show vlan brief',
    'show interfaces trunk',
    'show spanning-tree summary',
    'show cdp neighbors',
    'show logging',
    'show vtp status'
]

# Commands that need a longer read timeout due to potentially large output
LONG_TIMEOUT_CMDS = {'show run', 'show ip route'}
LONG_READ_TIMEOUT = 90
DEFAULT_READ_TIMEOUT = 30

# Get credentials securely
username = input("Enter your SSH username: ")
password = getpass.getpass("Enter your SSH password: ")
enable_secret = getpass.getpass("Enter your Enable Secret (press Enter if same as password): ") or password

# Create a directory for the logs
script_dir = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(script_dir, "network_audit_logs")
os.makedirs(log_dir, exist_ok=True)

# Read IP addresses from ips.txt located next to this script
ips_file = os.path.join(script_dir, 'ips.txt')
with open(ips_file, 'r', encoding='utf-8') as f:
    device_ips = [line.strip() for line in f if line.strip()]

failed_devices = []

for ip in device_ips:
    try:
        print(f"Connecting to {ip}...")

        device = {
            'device_type': 'cisco_ios',
            'host': ip,
            'username': username,
            'password': password,
            'secret': enable_secret,
            'conn_timeout': 15,
            'read_timeout_override': DEFAULT_READ_TIMEOUT,
        }

        # Context manager handles disconnect automatically, even on error
        with ConnectHandler(**device) as net_connect:

            if not net_connect.check_enable_mode():
                print(f"  Entering enable mode on {ip}...")
                net_connect.enable()

            # Sanitize hostname for safe use in a filename
            raw_prompt = net_connect.find_prompt()
            hostname = re.sub(r'[^\w.-]', '', raw_prompt)
            hostname = hostname or ip  # fallback if prompt is empty after stripping

            filename = os.path.join(log_dir, f"{hostname}_{ip}_audit.txt")

            with open(filename, 'w', encoding='utf-8') as log_file:
                for cmd in commands:
                    log_file.write(f"\n{'=' * 20} {cmd} {'=' * 20}\n")

                    read_timeout = LONG_READ_TIMEOUT if cmd in LONG_TIMEOUT_CMDS else DEFAULT_READ_TIMEOUT
                    output = net_connect.send_command(cmd, read_timeout=read_timeout)

                    log_file.write(output)
                    log_file.write("\n")

            print(f"  Done. Saved to {filename}")

    except Exception as e:
        print(f"  Failed to connect to {ip}: {e}")
        failed_devices.append((ip, str(e)))

# Write failed devices to a log
if failed_devices:
    failure_log = os.path.join(log_dir, "failed_devices.txt")
    with open(failure_log, 'w', encoding='utf-8') as f:
        for ip, reason in failed_devices:
            f.write(f"{ip}: {reason}\n")
    print(f"\nAudit complete. {len(failed_devices)} device(s) failed. See {failure_log}")
else:
    print("\nAudit complete. All devices succeeded.")
