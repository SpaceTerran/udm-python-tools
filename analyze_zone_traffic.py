#!/usr/bin/env python3
"""
Analyze Zone Traffic

Analyze firewall policies between specific zones to see what's allowed/blocked.
"""

import argparse
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def analyze_zone_traffic(client, src_zone_id, dst_zone_id, action_filter=None):
    """
    Analyze traffic between two zones.

    Args:
        client: UniFiFirewallClient instance
        src_zone_id: Source zone ID
        dst_zone_id: Destination zone ID
        action_filter: Filter by action (allow, block) or None for all

    Returns:
        Dictionary with allowed and blocked policies
    """
    all_policies = client.list_firewall_policies()
    
    allowed = []
    blocked = []
    
    for policy in all_policies:
        if not policy.get("enabled", False):
            continue
            
        source = policy.get("source", {})
        destination = policy.get("destination", {})
        
        if isinstance(source, dict) and isinstance(destination, dict):
            src_zone = source.get("zone_id", "")
            dst_zone = destination.get("zone_id", "")
            
            # Check if this policy matches our zone pair
            if src_zone == src_zone_id and dst_zone == dst_zone_id:
                policy_action = policy.get("action", "").upper()
                
                if action_filter:
                    if action_filter.upper() not in policy_action:
                        continue
                
                if policy_action == "ALLOW":
                    allowed.append(policy)
                elif policy_action == "BLOCK":
                    blocked.append(policy)
    
    return {
        "allowed": allowed,
        "blocked": blocked
    }


def main():
    """Analyze zone traffic."""
    parser = argparse.ArgumentParser(
        description="Analyze firewall policies between zones",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze traffic from External to DMZ
  python analyze_zone_traffic.py --src-zone 68236f2bbc658009c2e6668c --dst-zone 68236f2bbc658009c2e66690

  # Show only allowed traffic
  python analyze_zone_traffic.py --src-zone 68236f2bbc658009c2e6668c --dst-zone 68236f2bbc658009c2e66690 --action allow
        """
    )

    parser.add_argument("--src-zone", required=True, help="Source zone ID")
    parser.add_argument("--dst-zone", required=True, help="Destination zone ID")
    parser.add_argument("--action", choices=["allow", "block"], help="Filter by action")

    args = parser.parse_args()

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Analyze traffic
    print(f"\nAnalyzing traffic from zone {args.src_zone} to zone {args.dst_zone}...")
    results = analyze_zone_traffic(client, args.src_zone, args.dst_zone, args.action)

    # Display results
    print(f"\n{'='*70}")
    print("TRAFFIC ANALYSIS")
    print(f"{'='*70}\n")

    if args.action and args.action.lower() == "allow":
        policies = results["allowed"]
        print(f"ALLOWED POLICIES: {len(policies)}")
    elif args.action and args.action.lower() == "block":
        policies = results["blocked"]
        print(f"BLOCKED POLICIES: {len(policies)}")
    else:
        print(f"ALLOWED POLICIES: {len(results['allowed'])}")
        print(f"BLOCKED POLICIES: {len(results['blocked'])}")
        policies = results["allowed"] + results["blocked"]

    if not policies:
        print("\n  No matching policies found.")
        return

    print(f"{'='*70}\n")

    # Show allowed policies first
    if not args.action or args.action.lower() == "allow":
        if results["allowed"]:
            print("ALLOWED TRAFFIC:")
            print("-" * 70)
            for i, policy in enumerate(results["allowed"], 1):
                print(f"\nAllow Policy #{i}:")
                print(client.format_policy(policy))
                if i < len(results["allowed"]):
                    print("-" * 70)
            print()

    # Show blocked policies
    if not args.action or args.action.lower() == "block":
        if results["blocked"]:
            print("BLOCKED TRAFFIC:")
            print("-" * 70)
            for i, policy in enumerate(results["blocked"], 1):
                print(f"\nBlock Policy #{i}:")
                print(client.format_policy(policy))
                if i < len(results["blocked"]):
                    print("-" * 70)
            print()

    # Summary
    print(f"{'='*70}")
    print("SUMMARY:")
    print(f"  Allowed: {len(results['allowed'])} policy/policies")
    print(f"  Blocked: {len(results['blocked'])} policy/policies")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
