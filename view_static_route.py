#!/usr/bin/env python3
"""
View Static Route

View detailed information about a specific static route by ID.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """View a specific static route."""
    if len(sys.argv) < 2:
        print("Usage: python view_static_route.py <route_id>")
        print("\nTo list routes, run: python list_static_routes.py")
        sys.exit(1)

    route_id = sys.argv[1]

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Get the route
    print(f"\nFetching route: {route_id}...")
    route = client.get_static_route_by_id(route_id)

    if not route:
        print(f"✗ Route not found: {route_id}")
        print("\nTo list all routes, run: python list_static_routes.py")
        sys.exit(1)

    # Display formatted route
    print(f"\n{'='*70}")
    print("STATIC ROUTE DETAILS")
    print(f"{'='*70}\n")

    name = route.get("name", "Unnamed")
    enabled = "✓ Enabled" if route.get("enabled", True) else "✗ Disabled"
    network = route.get("static-route_network", "N/A")
    nexthop = route.get("static-route_nexthop", "N/A")
    distance = route.get("static-route_distance", 1)
    route_type = route.get("type", "nexthop-route")

    print(f"  Name: {name}")
    print(f"  ID: {route_id}")
    print(f"  Status: {enabled}")
    print(f"  Network: {network}")
    print(f"  Next Hop: {nexthop}")
    print(f"  Distance: {distance}")
    print(f"  Type: {route_type}")

    # Display full JSON for reference
    print(f"\n{'='*70}")
    print("FULL JSON DATA")
    print(f"{'='*70}\n")
    print(json.dumps(route, indent=2, default=str))


if __name__ == "__main__":
    main()
