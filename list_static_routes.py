#!/usr/bin/env python3
"""
List Static Routes

Lists all static routes from UniFi UDM Pro.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """List all static routes."""
    # Check for optional name filter
    name_filter = None
    if len(sys.argv) > 1:
        name_filter = sys.argv[1].lower()

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # List all routes
    print("\nFetching static routes...")
    all_routes = client.list_static_routes()

    if not all_routes:
        print("  No static routes found.")
        return

    # Filter by name if specified
    if name_filter:
        all_routes = [r for r in all_routes if name_filter in r.get("name", "").lower()]
        if not all_routes:
            print(f"  No routes matching '{name_filter}' found.")
            return

    print(f"\n{'='*70}")
    print(f"STATIC ROUTES: {len(all_routes)} total")
    print(f"{'='*70}\n")

    for route in all_routes:
        route_id = route.get("_id", "N/A")
        name = route.get("name", "Unnamed")
        enabled = "✓ Enabled" if route.get("enabled", True) else "✗ Disabled"
        network = route.get("static-route_network", "N/A")
        nexthop = route.get("static-route_nexthop", "N/A")
        distance = route.get("static-route_distance", 1)

        print(f"Name: {name}")
        print(f"  ID: {route_id}")
        print(f"  Status: {enabled}")
        print(f"  Network: {network}")
        print(f"  Next Hop: {nexthop}")
        print(f"  Distance: {distance}")
        print("-" * 70)

    print(f"\n{'='*70}")
    print(f"Total routes: {len(all_routes)}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
