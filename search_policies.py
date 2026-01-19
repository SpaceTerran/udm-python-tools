#!/usr/bin/env python3
"""
Search Firewall Policies

Search firewall policies by various criteria (name, port, IP, zone, etc.).
Returns matching policies with their details.
"""

import argparse
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def search_policies(client, name=None, port=None, ip=None, zone_id=None, protocol=None, action=None, enabled=None):
    """
    Search policies matching the given criteria.

    Args:
        client: UniFiFirewallClient instance
        name: Policy name (partial match, case-insensitive)
        port: Port number (matches source or destination port)
        ip: IP address (matches source or destination IP)
        zone_id: Zone ID (matches source or destination zone)
        protocol: Protocol (tcp, udp, etc.)
        action: Action (allow, block, etc.)
        enabled: Enabled status (true/false)

    Returns:
        List of matching policies
    """
    all_policies = client.list_firewall_policies()
    matches = []

    for policy in all_policies:
        match = True

        # Name search (partial match, case-insensitive)
        if name:
            policy_name = str(policy.get("name", "")).lower()
            if name.lower() not in policy_name:
                match = False

        # Port search (source or destination)
        if match and port:
            source = policy.get("source", {})
            destination = policy.get("destination", {})
            src_port = str(source.get("port", "") if isinstance(source, dict) else "")
            dst_port = str(destination.get("port", "") if isinstance(destination, dict) else "")
            if str(port) not in src_port and str(port) not in dst_port:
                match = False

        # IP search (source or destination)
        if match and ip:
            source = policy.get("source", {})
            destination = policy.get("destination", {})
            src_ips = source.get("ips", []) if isinstance(source, dict) else []
            dst_ips = destination.get("ips", []) if isinstance(destination, dict) else []
            all_ips = src_ips + dst_ips
            if not any(ip in str(addr) for addr in all_ips):
                match = False

        # Zone ID search (source or destination)
        if match and zone_id:
            source = policy.get("source", {})
            destination = policy.get("destination", {})
            src_zone = source.get("zone_id", "") if isinstance(source, dict) else ""
            dst_zone = destination.get("zone_id", "") if isinstance(destination, dict) else ""
            if zone_id not in str(src_zone) and zone_id not in str(dst_zone):
                match = False

        # Protocol search
        if match and protocol:
            policy_protocol = str(policy.get("protocol", "")).lower()
            if protocol.lower() not in policy_protocol:
                match = False

        # Action search
        if match and action:
            policy_action = str(policy.get("action", "")).lower()
            if action.lower() not in policy_action:
                match = False

        # Enabled status
        if match and enabled is not None:
            policy_enabled = policy.get("enabled", True)
            if enabled != policy_enabled:
                match = False

        if match:
            matches.append(policy)

    return matches


def main():
    """Search firewall policies."""
    parser = argparse.ArgumentParser(
        description="Search firewall policies by various criteria",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Search by name
  python search_policies.py --name tailscale

  # Search by port
  python search_policies.py --port 41641

  # Search by IP
  python search_policies.py --ip 192.168.53.235

  # Search by zone ID
  python search_policies.py --zone-id 68236f2bbc658009c2e6668c

  # Search by protocol
  python search_policies.py --protocol udp

  # Search by action
  python search_policies.py --action allow

  # Search only active policies
  python search_policies.py --enabled true

  # Combine criteria
  python search_policies.py --name tailscale --port 41641 --protocol udp
        """
    )

    parser.add_argument("--name", help="Policy name (partial match)")
    parser.add_argument("--port", help="Port number (source or destination)")
    parser.add_argument("--ip", help="IP address (source or destination)")
    parser.add_argument("--zone-id", help="Zone ID (source or destination)")
    parser.add_argument("--protocol", help="Protocol (tcp, udp, etc.)")
    parser.add_argument("--action", help="Action (allow, block, etc.)")
    parser.add_argument("--enabled", type=str, choices=["true", "false"], help="Enabled status")

    args = parser.parse_args()

    # Check if at least one search criterion is provided
    if not any([args.name, args.port, args.ip, args.zone_id, args.protocol, args.action, args.enabled]):
        parser.print_help()
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

    # Convert enabled string to boolean
    enabled_bool = None
    if args.enabled:
        enabled_bool = args.enabled.lower() == "true"

    # Search policies
    print("\nSearching firewall policies...")
    matches = search_policies(
        client,
        name=args.name,
        port=args.port,
        ip=args.ip,
        zone_id=args.zone_id,
        protocol=args.protocol,
        action=args.action,
        enabled=enabled_bool,
    )

    # Display results
    if matches:
        print(f"\n{'='*70}")
        print(f"FOUND {len(matches)} MATCHING POLICY/POLICIES")
        print(f"{'='*70}\n")

        for i, policy in enumerate(matches, 1):
            print(f"Match #{i}:")
            print(client.format_policy(policy))
            if i < len(matches):
                print("-" * 70)
                print()

        print(f"{'='*70}")
        print(f"Total matches: {len(matches)}")
        print(f"{'='*70}")
    else:
        print("\nNo matching policies found.")
        print("\nTo list all policies, run: python list_policies.py")


if __name__ == "__main__":
    main()
