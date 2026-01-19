#!/usr/bin/env python3
"""
Create Static Route

Create a new static route. Can be created from JSON file or via command-line arguments.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Create a static route."""
    if len(sys.argv) < 4:
        print("Usage: python create_static_route.py <name> <network> <nexthop> [distance] [enabled]")
        print("   OR: python create_static_route.py <route_json_file>")
        print("\nExamples:")
        print("  # Create simple route")
        print("  python create_static_route.py 'VPN Route' 10.0.0.0/24 192.168.1.1")
        print("\n  # Create with custom distance")
        print("  python create_static_route.py 'VPN Route' 10.0.0.0/24 192.168.1.1 10")
        print("\n  # Create disabled route")
        print("  python create_static_route.py 'VPN Route' 10.0.0.0/24 192.168.1.1 1 false")
        print("\n  # Create from JSON file")
        print("  python create_static_route.py route.json")
        print("\nJSON file format:")
        print('  {')
        print('    "name": "VPN Route",')
        print('    "network": "10.0.0.0/24",')
        print('    "nexthop": "192.168.1.1",')
        print('    "distance": 1,')
        print('    "enabled": true')
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

    # Handle command-line arguments
    if len(sys.argv) == 2:
        # Load from JSON file
        try:
            with open(sys.argv[1], "r") as f:
                route_data = json.load(f)
        except FileNotFoundError:
            print(f"✗ File not found: {sys.argv[1]}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"✗ Invalid JSON: {e}")
            sys.exit(1)

        name = route_data.get("name")
        network = route_data.get("network")
        nexthop = route_data.get("nexthop")
        distance = route_data.get("distance", 1)
        enabled = route_data.get("enabled", True)
    else:
        # Command-line arguments
        name = sys.argv[1]
        network = sys.argv[2]
        nexthop = sys.argv[3]
        distance = int(sys.argv[4]) if len(sys.argv) > 4 else 1
        enabled_str = sys.argv[5].lower() if len(sys.argv) > 5 else "true"
        enabled = enabled_str in ["true", "1", "yes", "enabled"]

    # Validate required fields
    if not name or not network or not nexthop:
        print("✗ Error: name, network, and nexthop are required")
        sys.exit(1)

    print(f"\nCreating static route: {name}")
    print(f"  Network: {network}")
    print(f"  Next Hop: {nexthop}")
    print(f"  Distance: {distance}")
    print(f"  Enabled: {enabled}")

    # Create the route
    result = client.create_static_route(name, network, nexthop, distance, enabled)

    if result:
        route_id = result.get("_id") if isinstance(result, dict) else None
        if route_id:
            print(f"\n✓ Successfully created static route with ID: {route_id}")
            print("\nRoute details:")
            print(f"  Name: {name}")
            print(f"  ID: {route_id}")
            print(f"  Network: {network}")
            print(f"  Next Hop: {nexthop}")
            print(f"  Distance: {distance}")
        else:
            print(f"\n✓ Static route created (response: {result})")
    else:
        print("\n✗ Failed to create static route")
        sys.exit(1)


if __name__ == "__main__":
    main()
