#!/usr/bin/env python3
"""
Create Firewall Group

Create a new firewall group (IP/port group). Can be created from JSON file
or via command-line arguments.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Create a firewall group."""
    if len(sys.argv) < 2:
        print("Usage: python create_group.py <group_json_file>")
        print("   OR: python create_group.py --address <name> <members...>")
        print("   OR: python create_group.py --port <name> <members...>")
        print("\nExamples:")
        print("  # Create address group from command line")
        print("  python create_group.py --address 'My IPs' 1.1.1.0/24 2.2.2.0/24")
        print("\n  # Create port group from command line")
        print("  python create_group.py --port 'Web Ports' 80 443 8080")
        print("\n  # Create from JSON file")
        print("  python create_group.py group.json")
        print("\nJSON file format:")
        print('  {')
        print('    "name": "Group Name",')
        print('    "group_type": "address-group",  # or "port-group"')
        print('    "group_members": ["1.1.1.0/24", "2.2.2.0/24"]')
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

    # Handle command-line quick-create options
    if sys.argv[1] == "--address":
        if len(sys.argv) < 4:
            print("✗ Error: --address requires name and at least one member")
            print("Usage: python create_group.py --address <name> <members...>")
            sys.exit(1)
        group_data = {
            "name": sys.argv[2],
            "group_type": "address-group",
            "group_members": sys.argv[3:],
        }
    elif sys.argv[1] == "--port":
        if len(sys.argv) < 4:
            print("✗ Error: --port requires name and at least one member")
            print("Usage: python create_group.py --port <name> <members...>")
            sys.exit(1)
        group_data = {
            "name": sys.argv[2],
            "group_type": "port-group",
            "group_members": sys.argv[3:],
        }
    else:
        # Load from JSON file
        try:
            with open(sys.argv[1], "r") as f:
                group_data = json.load(f)
        except FileNotFoundError:
            print(f"✗ File not found: {sys.argv[1]}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"✗ Invalid JSON: {e}")
            sys.exit(1)

    # Validate required fields
    if "name" not in group_data:
        print("✗ Error: 'name' field is required")
        sys.exit(1)
    if "group_type" not in group_data:
        print("✗ Error: 'group_type' field is required (e.g., 'address-group' or 'port-group')")
        sys.exit(1)
    if "group_members" not in group_data:
        group_data["group_members"] = []

    print(f"\nCreating group: {group_data.get('name', 'Unnamed')}")
    print(f"Type: {group_data.get('group_type', 'unknown')}")
    print(f"Members ({len(group_data.get('group_members', []))}):")
    for member in group_data.get("group_members", []):
        print(f"  - {member}")

    # Create the group
    result = client.create_firewall_group(
        name=group_data["name"],
        group_type=group_data["group_type"],
        members=group_data["group_members"],
    )

    if result:
        group_id = result.get("_id") if isinstance(result, dict) else None
        if isinstance(result, dict) and "data" in result:
            # Response might be wrapped in data array
            data_list = result["data"]
            if isinstance(data_list, list) and len(data_list) > 0:
                group_id = data_list[0].get("_id")
        if group_id:
            print(f"\n✓ Successfully created group with ID: {group_id}")
            print("\nGroup details:")
            print(f"  Name: {group_data['name']}")
            print(f"  ID: {group_id}")
            print(f"  Type: {group_data['group_type']}")
            print(f"  Members: {', '.join(group_data['group_members'])}")
        else:
            print(f"\n✓ Group created (response: {result})")
    else:
        print("\n✗ Failed to create group")
        sys.exit(1)


if __name__ == "__main__":
    main()
