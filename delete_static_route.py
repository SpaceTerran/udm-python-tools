#!/usr/bin/env python3
"""
Delete Static Route

Delete a static route by ID.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Delete a static route."""
    if len(sys.argv) < 2:
        print("Usage: python delete_static_route.py <route_id>")
        print("\nTo get route IDs, run: python list_static_routes.py")
        sys.exit(1)

    route_id = sys.argv[1]

    # Check for --force flag
    force = "--force" in sys.argv

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Get current route to show what we're deleting
    route = client.get_static_route_by_id(route_id)
    if not route:
        print(f"✗ Route not found: {route_id}")
        sys.exit(1)

    name = route.get("name", "Unnamed")
    network = route.get("static-route_network", "N/A")
    nexthop = route.get("static-route_nexthop", "N/A")

    print("\nStatic route to delete:")
    print(f"  Name: {name}")
    print(f"  ID: {route_id}")
    print(f"  Network: {network}")
    print(f"  Next Hop: {nexthop}")

    # Confirm deletion unless --force is used
    if not force:
        response = input("\nAre you sure you want to delete this static route? [y/N]: ")
        if response.lower() != "y":
            print("Aborted.")
            sys.exit(0)

    print(f"\nDeleting static route {route_id}...")

    # Delete the route
    success = client.delete_static_route(route_id)

    if success:
        print(f"✓ Successfully deleted static route: {name}")
    else:
        print(f"✗ Failed to delete static route: {route_id}")
        sys.exit(1)


if __name__ == "__main__":
    main()
