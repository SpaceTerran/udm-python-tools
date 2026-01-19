# UniFi Inventory

This file contains basic inventory information for your UniFi environment. Update this file with your specific zone IDs, key IP addresses, and other environment-specific details.

**Note:** This file is intended to be committed to version control as a template. Replace placeholder values with your actual environment details.

## Zone IDs

UniFi uses zones to group networks. Each zone has a unique ID that you'll need when creating firewall policies.

| Zone Name | Zone ID | Description |
|-----------|---------|-------------|
| External | `YOUR_EXTERNAL_ZONE_ID` | Internet/WAN traffic |
| Internal | `YOUR_INTERNAL_ZONE_ID` | Trusted internal networks (Default, Trusted, etc.) |
| DMZ | `YOUR_DMZ_ZONE_ID` | Demilitarized zone (semi-trusted) |
| VPN | `YOUR_VPN_ZONE_ID` | VPN network zone (if applicable) |
| Guest | `YOUR_GUEST_ZONE_ID` | Guest network zone (if applicable) |

**How to find your zone IDs:**
```bash
source venv/bin/activate
python -c "from dotenv import load_dotenv; from unifi_client import get_client_from_env; load_dotenv(); c = get_client_from_env(); c.login(); configs = c.get_network_configs(); [print(f\"{n.get('name', 'Unknown')}: {n.get('zone_id', 'N/A')}\") for n in configs]"
```

Or use the UniFi UI: Settings → Networks → [Select Network] → Advanced → Zone

## Key IP Addresses

Document important IP addresses in your environment for reference when creating firewall rules, port forwards, or static routes.

### Network Ranges
- **Internal Network:** `192.168.1.0/24` (example)
- **DMZ Network:** `192.168.4.0/24` (example)
- **VPN Network:** `10.0.0.0/24` (example)

### Key Servers/Devices
| Device/Service | IP Address | Notes |
|----------------|------------|-------|
| UDM Pro | `192.168.1.1` | UniFi Dream Machine Pro |
| Example Server | `192.168.1.100` | Description |
| Example DMZ Server | `192.168.4.10` | Description |

## Common Policy IDs

If you have frequently referenced policies, document them here for quick reference:

| Policy Name | Policy ID | Purpose |
|-------------|-----------|---------|
| Example Policy | `YOUR_POLICY_ID` | Description |

**Note:** Policy IDs can be found using `python list_policies.py`

## Common Group IDs

Document frequently used firewall groups:

| Group Name | Group ID | Type | Purpose |
|------------|----------|------|---------|
| Cloudflare IPs | `YOUR_GROUP_ID` | address-group | Cloudflare IP ranges |
| Web Ports | `YOUR_GROUP_ID` | port-group | Common web service ports |

**Note:** Group IDs can be found using `python list_groups.py`

## Port Forwarding Rules

Document important port forwarding rules for reference:

| Rule Name | Rule ID | External Port | Internal IP:Port | Protocol |
|-----------|---------|---------------|------------------|----------|
| Example Rule | `YOUR_RULE_ID` | 443 | 192.168.1.100:443 | tcp |

**Note:** Port forward IDs can be found using `python list_port_forwards.py`

## Static Routes

Document static routes for reference:

| Route Name | Route ID | Network | Next Hop | Distance |
|------------|----------|---------|----------|----------|
| Example Route | `YOUR_ROUTE_ID` | 10.0.0.0/24 | 192.168.1.1 | 1 |

**Note:** Static route IDs can be found using `python list_static_routes.py`

## Notes

Add any other environment-specific notes or configurations here:

- Custom network configurations
- Special firewall rule patterns
- Important reminders about your setup
