#!/usr/bin/env python3
"""
Create Port Forwarding Rule

Create a new port forwarding rule. Can be created from JSON file
or via command-line arguments.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Create a port forwarding rule."""
    if len(sys.argv) < 2:
        print("Usage: python create_port_forward.py <rule_json_file>")
        print("   OR: python create_port_forward.py --simple <name> <ext_port> <int_ip> [int_port] [protocol] [src_ip]")
        print("\nExamples:")
        print("  # Create simple port forward (internal port defaults to external port)")
        print("  python create_port_forward.py --simple 'Web Server' 80 192.168.1.100")
        print("\n  # Create with different internal port")
        print("  python create_port_forward.py --simple 'Web Server' 80 192.168.1.100 8080")
        print("\n  # Create with specific protocol")
        print("  python create_port_forward.py --simple 'Web Server' 80 192.168.1.100 8080 tcp")
        print("\n  # Create with source IP restriction")
        print("  python create_port_forward.py --simple 'Tailscale' 41641 192.168.53.235 41641 udp 72.62.6.185/32")
        print("\n  # Create from JSON file")
        print("  python create_port_forward.py rule.json")
        print("\nJSON file format:")
        print('  {')
        print('    "name": "Web Server",')
        print('    "dst_port": "80",')
        print('    "fwd_port": "8080",')
        print('    "fwd_ip": "192.168.1.100",')
        print('    "proto": "tcp",  # or "udp", "tcp_udp"')
        print('    "enabled": true,')
        print('    "src": "1.2.3.4",  # optional source IP')
        print('    "log": false  # optional logging')
        print('  }')
        sys.exit(1)

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Handle command-line quick-create option
    if sys.argv[1] == "--simple":
        if len(sys.argv) < 5:
            print("✗ Error: --simple requires name, external port, and internal IP")
            print("Usage: python create_port_forward.py --simple <name> <ext_port> <int_ip> [int_port] [protocol]")
            sys.exit(1)

        name = sys.argv[2]
        dst_port = sys.argv[3]
        fwd_ip = sys.argv[4]
        fwd_port = sys.argv[5] if len(sys.argv) > 5 else dst_port
        proto = sys.argv[6] if len(sys.argv) > 6 else "tcp_udp"
        src_ip = sys.argv[7] if len(sys.argv) > 7 else None

        # Normalize protocol
        if proto.lower() in ["tcp", "udp", "tcp_udp"]:
            proto = proto.lower()
        elif proto.lower() == "both":
            proto = "tcp_udp"
        else:
            print(f"✗ Invalid protocol: {proto}. Use 'tcp', 'udp', or 'tcp_udp'")
            sys.exit(1)

        rule_data = {
            "name": name,
            "dst_port": dst_port,
            "fwd_port": fwd_port,
            "fwd_ip": fwd_ip,
            "proto": proto,
            "enabled": True,
        }
        
        # Add source IP if provided (will automatically set src_limiting_enabled and src_limiting_type in client)
        if src_ip:
            rule_data["src"] = src_ip
            rule_data["log"] = True  # Default to logging when source IP is restricted
    else:
        # Load from JSON file
        try:
            with open(sys.argv[1], "r") as f:
                rule_data = json.load(f)
        except FileNotFoundError:
            print(f"✗ File not found: {sys.argv[1]}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"✗ Invalid JSON: {e}")
            sys.exit(1)

    # Validate required fields
    required_fields = ["name", "dst_port", "fwd_port", "fwd_ip"]
    missing = [f for f in required_fields if f not in rule_data]
    if missing:
        print(f"✗ Error: Missing required fields: {', '.join(missing)}")
        sys.exit(1)

    print(f"\nCreating port forward: {rule_data.get('name', 'Unnamed')}")
    print(f"  External Port: {rule_data.get('dst_port')}")
    print(f"  Forward To: {rule_data.get('fwd_ip')}:{rule_data.get('fwd_port')}")
    print(f"  Protocol: {rule_data.get('proto', 'tcp_udp')}")
    if rule_data.get("src"):
        print(f"  Source IP: {rule_data.get('src')}")

    # Create the rule
    result = client.create_port_forward(rule_data)

    if result:
        rule_id = result.get("_id") if isinstance(result, dict) else None
        if rule_id:
            print(f"\n✓ Successfully created port forward with ID: {rule_id}")
            print("\nRule details:")
            print(f"  Name: {rule_data['name']}")
            print(f"  ID: {rule_id}")
            print(f"  External Port: {rule_data['dst_port']}")
            print(f"  Forward To: {rule_data['fwd_ip']}:{rule_data['fwd_port']}")
            print(f"  Protocol: {rule_data.get('proto', 'tcp_udp')}")
        else:
            print(f"\n✓ Port forward created (response: {result})")
    else:
        print("\n✗ Failed to create port forward")
        sys.exit(1)


if __name__ == "__main__":
    main()
