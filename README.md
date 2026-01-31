# UniFi Firewall Tool

CLI tools for managing UniFi UDM Pro firewall policies and groups via the REST API.

## Attributions and Third-Party Components

**Important:** This project uses and references several third-party components that are not owned or created by the author:

- **UniFi** - UniFi, UDM Pro, and all related trademarks are property of [Ubiquiti Inc.](https://www.ui.com/). This project is not affiliated with, endorsed by, or associated with Ubiquiti Inc.
- **Python** - Python programming language is developed by the [Python Software Foundation](https://www.python.org/psf/). This project uses Python but does not claim ownership of the language.
- **unifi-network-mcp submodule** - The `unifi-network-mcp` submodule included in this repository is **not my code**. It is included as a reference implementation and is the work of [sirkirby](https://github.com/sirkirby/unifi-network-mcp). All credit for the submodule code belongs to its original author. This project uses it only as a reference for API endpoints and patterns.
- **Third-party Python packages** - This project uses various open-source Python packages (see `requirements.txt`). Each package maintains its own license and copyright.

This repository contains only the wrapper scripts, client library, and tooling created by the author. All third-party components retain their original licenses and copyrights.

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

**DNS Records Management (Policy Table → DNS Records):**

These scripts manage **gateway-level static DNS records** (UniFi Network → Settings → Policy Table → DNS Records), not per-client local hostnames.

- `list_policy_dns_records.py [filter]` - List all DNS records with optional domain filter
- `view_policy_dns_record.py <domain_or_id>` - View a DNS record by domain or ID
- `create_policy_dns_record.py <json_file>` - Create a DNS record from JSON file
- `create_policy_dns_record.py --simple <domain> <value> [type] [ttl]` - Create a DNS record from CLI
- `update_policy_dns_record.py <record_id> <json_file>` - Update a DNS record from JSON file
- `update_policy_dns_record.py <record_id> '<json_string>'` - Update a DNS record with inline JSON
- `delete_policy_dns_record.py <record_id> [--force]` - Delete a DNS record

**Analysis:**
- `analyze_zone_traffic.py` - Analyze allowed/blocked traffic between zones

### Inventory Files

- `unifi-inventory.md` - Environment-specific inventory: zone IDs, key IP addresses, policy IDs, group IDs, port forwards, and static routes
- `unifi-inventory-example.md` - Template for documenting UniFi environment-specific details
- `proxmox-inventory.md` - Complete inventory of Proxmox cluster VMs and LXC containers, including IP addresses, SSH connection details, and node information

## Usage Examples

### DNS Records (policy-based static DNS)

```bash
# List all DNS records
python list_policy_dns_records.py

# List with domain filter
python list_policy_dns_records.py spaceterran

# View a specific record
python view_policy_dns_record.py scrypted.spaceterran.com

# Create a new A record (simple mode)
python create_policy_dns_record.py --simple myserver.example.com 192.168.1.100

# Create with specific type and TTL
python create_policy_dns_record.py --simple myserver.example.com 192.168.1.100 A 300

# Create from JSON file
python create_policy_dns_record.py record.json

# Update a record (inline JSON)
python update_policy_dns_record.py 6831f9f5c8ac4702c97c5e1e '{"value": "192.168.1.200"}'

# Delete a record (with confirmation)
python delete_policy_dns_record.py 6831f9f5c8ac4702c97c5e1e

# Delete without confirmation
python delete_policy_dns_record.py 6831f9f5c8ac4702c97c5e1e --force
```

**DNS Record JSON format:**
```json
{
  "key": "myserver.example.com",
  "value": "192.168.1.100",
  "record_type": "A",
  "ttl": 0,
  "enabled": true
}
```

Supported record types: `A`, `AAAA`, `CNAME`, `MX`, `SRV`, `TXT`

## Submodule Usage

The `unifi-network-mcp` submodule is included **only as a reference** for discovering API endpoints, patterns, and implementation examples.

**Big thanks to [unifi-network-mcp](https://github.com/sirkirby/unifi-network-mcp)** for saving me countless cycles in understanding the UniFi API. If you find this project useful, please consider [starring their repository](https://github.com/sirkirby/unifi-network-mcp) to show your appreciation.

---

### Technical note: DNS scripts

The DNS scripts in this repo target **policy-based static DNS** (Policy Table → DNS Records; API `/proxy/network/v2/api/site/{site}/static-dns`). An earlier set of scripts (`create_dns_record`, `list_dns_records`, etc.) targeted **local/client hostnames** (per-device, MAC-based; UniFi “user” API with `local_dns_record`). That was not the originally intended design; the repo now uses only the policy-based static DNS scripts above.
