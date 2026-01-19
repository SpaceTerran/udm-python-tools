#!/usr/bin/env python3
"""
Update Static Route

Update a static route with JSON data.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Update a static route."""
    if len(sys.argv) < 3:
        print("Usage: python update_static_route.py <route_id> <json_file>")
        print("   OR: python update_static_route.py <route_id> '<json_string>'")
        print("\nExamples:")
        print("  # Update from JSON file")
        print("  python update_static_route.py 6831f9f5c8ac4702c97c5e1e updates.json")
        print("\n  # Update with inline JSON")
        print('  python update_static_route.py 6831f9f5c8ac4702c97c5e1e \'{"enabled": false}\'')
        print("\nTo get route IDs, run: python list_static_routes.py")
        sys.exit(1)

    route_id = sys.argv[1]
    json_input = sys.argv[2]

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Get current route to show what we're updating
    route = client.get_static_route_by_id(route_id)
    if not route:
        print(f"✗ Route not found: {route_id}")
        sys.exit(1)

    print(f"\nCurrent route: {route.get('name', 'Unnamed')}")
    print(f"  Network: {route.get('static-route_network', 'N/A')}")
    print(f"  Next Hop: {route.get('static-route_nexthop', 'N/A')}")
    print(f"  Distance: {route.get('static-route_distance', 'N/A')}")
    print(f"  Enabled: {route.get('enabled', True)}")

    # Parse JSON input
    try:
        if json_input.startswith("{") or json_input.startswith("["):
            # Inline JSON string
            update_data = json.loads(json_input)
        else:
            # JSON file
            with open(json_input, "r") as f:
                update_data = json.load(f)
    except FileNotFoundError:
        print(f"✗ File not found: {json_input}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON: {e}")
        sys.exit(1)

    # Convert field names if needed (network -> static-route_network, etc.)
    converted_data = {}
    for key, value in update_data.items():
        if key == "network":
            converted_data["static-route_network"] = value
        elif key == "nexthop":
            converted_data["static-route_nexthop"] = value
        elif key == "distance":
            converted_data["static-route_distance"] = value
        else:
            converted_data[key] = value

    print("\nUpdating with:")
    print(json.dumps(converted_data, indent=2))

    # Update the route (with verification enabled by default)
    success = client.update_static_route(route_id, converted_data, verify=True)

    if success:
        print(f"\n✓ Successfully updated and verified static route: {route.get('name', route_id)}")
    else:
        print(f"\n✗ Failed to update static route: {route_id}")
        print("  The update may have been rejected by the API or verification failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
