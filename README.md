# UniFi Firewall Tool

CLI tools for managing UniFi UDM Pro firewall policies and groups via the REST API.

## Overview

This project provides standalone Python scripts to manage firewall policies, groups, port forwarding, static routes, and DNS records on a UniFi Dream Machine Pro. Each script performs a single operation (list, view, create, update, delete, enable, disable) following a modular design.

## Modules

### Core Client Library

**`unifi_client.py`** - Shared client providing authentication and API methods with automatic rate limiting:
- Firewall policy management (list, create, update, delete, toggle)
- Firewall group management (IP/port groups)
- Port forwarding management
- Static route management
- DNS record management
- Network configuration and zone discovery
- Automatic rate limiting with exponential backoff retry logic
- Encrypted password support via `get_client_from_env()`

### Password Manager

**`password_manager.py`** - Utility for securely managing encrypted passwords:
- Encrypts passwords using system-specific key derivation
- Stores encrypted passwords in `.env.password.encrypted` (git-ignored, permissions 600)
- Automatically integrated with `get_client_from_env()`

### Script Modules

**Policy Management:**
- `list_policies.py` - List all policies with IDs, names, and status
- `view_policy.py` - View full details of a specific policy
- `search_policies.py` - Search policies by name, port, IP, zone, protocol, or action
- `create_policy.py` - Create a new policy from JSON or preset
- `update_policy.py` - Update a policy with JSON data
- `enable_policy.py` / `disable_policy.py` - Toggle policy status
- `delete_policy.py` - Delete a policy

**Group Management:**
- `list_groups.py` - List firewall groups (IP/port groups)
- `view_group.py` - View group details and members
- `create_group.py` - Create a new firewall group (from JSON or CLI)
- `update_group.py` - Add, remove, or set group members
- `delete_group.py` - Delete a firewall group
- `sync_cloudflare_ips.py` - Sync Cloudflare IP ranges from official API

**Port Forwarding Management:**
- `list_port_forwards.py` - List all port forwarding rules
- `view_port_forward.py` - View port forward rule details
- `create_port_forward.py` - Create a new port forwarding rule (from JSON or CLI)
- `update_port_forward.py` - Update a port forward rule with JSON data
- `enable_port_forward.py` / `disable_port_forward.py` - Toggle port forward status
- `delete_port_forward.py` - Delete a port forward rule

**Static Routes Management:**
- `list_static_routes.py` - List all static routes
- `view_static_route.py` - View static route details
- `create_static_route.py` - Create a new static route (from JSON or CLI)
- `update_static_route.py` - Update a static route with JSON data
- `delete_static_route.py` - Delete a static route

**DNS Records Management:**
- `list_dns_records.py` - List all DNS records (local DNS hostnames)
- `view_dns_record.py` - View DNS record details by MAC address
- `create_dns_record.py` - Create a DNS record for a client
- `update_dns_record.py` - Update a DNS record hostname
- `delete_dns_record.py` - Delete a DNS record (disable local DNS)

**Analysis:**
- `analyze_zone_traffic.py` - Analyze allowed/blocked traffic between zones

### Inventory Files

- `unifi-inventory.md` - Environment-specific inventory: zone IDs, key IP addresses, policy IDs, group IDs, port forwards, and static routes
- `unifi-inventory-example.md` - Template for documenting UniFi environment-specific details
- `proxmox-inventory.md` - Complete inventory of Proxmox cluster VMs and LXC containers, including IP addresses, SSH connection details, and node information

## Submodule Usage

The `unifi-network-mcp` submodule is included **only as a reference** for discovering API endpoints, patterns, and implementation examples.

**Big thanks to [unifi-network-mcp](https://github.com/sirkirby/unifi-network-mcp)** for saving me countless cycles in understanding the UniFi API. If you find this project useful, please consider [starring their repository](https://github.com/sirkirby/unifi-network-mcp) to show your appreciation.

## License

MIT
