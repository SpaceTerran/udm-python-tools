#!/usr/bin/env python3
"""
UniFi Firewall API Client

Shared client class for interacting with UniFi UDM Pro firewall API.
"""

import copy
import os
import time
from typing import Any, Callable, Dict, Optional

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Validation constants
VALID_ACTIONS = {"ALLOW", "BLOCK", "ACCEPT", "DROP", "REJECT"}
VALID_ACTIONS_LOWER = {a.lower() for a in VALID_ACTIONS}
VALID_PROTOCOLS = {"tcp", "udp", "tcp_udp", "all", "icmp", "icmpv6"}
VALID_IP_VERSIONS = {"IPV4", "IPV6", "BOTH"}
VALID_CONNECTION_STATE_TYPES = {"ALL", "CUSTOM", "INCLUSIVE"}
VALID_CONNECTION_STATES = {"NEW", "ESTABLISHED", "RELATED", "INVALID"}


def validate_action(action: str) -> tuple[bool, str]:
    """
    Validate and normalize action value.
    
    Args:
        action: Action string to validate
        
    Returns:
        Tuple of (is_valid, normalized_action or error_message)
    """
    if not action:
        return False, "Action cannot be empty"
    
    action_upper = action.upper()
    action_lower = action.lower()
    
    # Check if it's a valid action (case-insensitive)
    if action_upper in VALID_ACTIONS:
        return True, action_upper
    elif action_lower in VALID_ACTIONS_LOWER:
        # Map lowercase/common variations to API-expected uppercase
        mapping = {
            "allow": "ALLOW",
            "block": "BLOCK",
            "accept": "ALLOW",  # ACCEPT is typically mapped to ALLOW
            "drop": "BLOCK",    # DROP maps to BLOCK in UniFi API
            "reject": "REJECT"
        }
        normalized = mapping.get(action_lower, action_upper)
        return True, normalized
    else:
        valid_options = ", ".join(sorted(VALID_ACTIONS))
        return False, f"Invalid action '{action}'. Must be one of: {valid_options} (case-insensitive, but API expects uppercase: ALLOW, BLOCK, or REJECT)"


def validate_policy_data(policy_data: Dict[str, Any]) -> tuple[bool, Optional[str]]:
    """
    Validate firewall policy data before sending to API.
    
    Args:
        policy_data: Policy data dictionary
        
    Returns:
        Tuple of (is_valid, error_message or None)
    """
    errors = []
    
    # Validate action
    if "action" in policy_data:
        is_valid, result = validate_action(policy_data["action"])
        if not is_valid:
            errors.append(result)
        else:
            # Normalize the action
            policy_data["action"] = result
    
    # Validate protocol
    if "protocol" in policy_data:
        protocol = str(policy_data["protocol"]).lower()
        if protocol not in VALID_PROTOCOLS:
            valid_protocols = ", ".join(sorted(VALID_PROTOCOLS))
            errors.append(f"Invalid protocol '{policy_data['protocol']}'. Must be one of: {valid_protocols}")
        else:
            policy_data["protocol"] = protocol
    
    # Validate ip_version
    if "ip_version" in policy_data:
        ip_version = str(policy_data["ip_version"]).upper()
        if ip_version not in VALID_IP_VERSIONS:
            valid_versions = ", ".join(sorted(VALID_IP_VERSIONS))
            errors.append(f"Invalid ip_version '{policy_data['ip_version']}'. Must be one of: {valid_versions}")
        else:
            policy_data["ip_version"] = ip_version
    
    # Validate connection_state_type
    if "connection_state_type" in policy_data:
        state_type = str(policy_data["connection_state_type"]).upper()
        if state_type not in VALID_CONNECTION_STATE_TYPES:
            valid_types = ", ".join(sorted(VALID_CONNECTION_STATE_TYPES))
            errors.append(f"Invalid connection_state_type '{policy_data['connection_state_type']}'. Must be one of: {valid_types}")
        else:
            policy_data["connection_state_type"] = state_type
    
    # Validate connection_states if CUSTOM
    if "connection_states" in policy_data and isinstance(policy_data["connection_states"], list):
        if policy_data.get("connection_state_type") == "CUSTOM":
            invalid_states = [s for s in policy_data["connection_states"] if str(s).upper() not in VALID_CONNECTION_STATES]
            if invalid_states:
                valid_states = ", ".join(sorted(VALID_CONNECTION_STATES))
                errors.append(f"Invalid connection_states {invalid_states}. Must be one of: {valid_states}")
            else:
                # Normalize to uppercase
                policy_data["connection_states"] = [str(s).upper() for s in policy_data["connection_states"]]
    
    if errors:
        return False, "Validation errors:\n  - " + "\n  - ".join(errors)
    
    return True, None


class UniFiFirewallClient:
    """Client for interacting with UniFi UDM Pro firewall API."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        site: str = "default",
        verify_ssl: bool = False,
    ):
        """
        Initialize the UniFi firewall client.

        Args:
            host: UDM Pro IP address or hostname
            username: Local admin username
            password: Admin password
            site: Site identifier (usually 'default')
            verify_ssl: Whether to verify SSL certificates
        """
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.site = site
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.csrf_token: Optional[str] = None

    def _retry_with_backoff(
        self,
        request_func: Callable,
        max_retries: int = 10,
        initial_delay: float = 3.0,
        max_delay: float = 300.0,
    ) -> Any:
        """
        Retry a request function with exponential backoff on rate limit errors.

        Args:
            request_func: Function that makes the HTTP request and returns response
            max_retries: Maximum number of retry attempts (default: 10)
            initial_delay: Initial delay in seconds (default: 3.0)
            max_delay: Maximum delay in seconds (default: 300.0)

        Returns:
            Response from request_func, or None if all retries exhausted
        """
        delay = initial_delay
        attempt = 0

        while attempt < max_retries:
            try:
                response = request_func()
                # Check if response indicates rate limiting
                if hasattr(response, 'status_code') and response.status_code == 429:
                    error_msg = "Too Many Requests"
                    if hasattr(response, 'text'):
                        error_msg = response.text or error_msg
                    print(f"⚠ Rate limited (429) on attempt {attempt + 1}/{max_retries}. Waiting {delay:.1f}s before retry...")
                    time.sleep(delay)
                    # Exponential backoff: 3s, 6s, 12s, 24s, 48s, 96s, 192s, max 300s
                    delay = min(delay * 2, max_delay)
                    attempt += 1
                    continue
                # Success - return response
                return response
            except requests.exceptions.HTTPError as e:
                # Check if it's a 429 error
                if hasattr(e.response, 'status_code') and e.response.status_code == 429:
                    error_msg = str(e)
                    print(f"⚠ Rate limited (429) on attempt {attempt + 1}/{max_retries}: {error_msg}")
                    print(f"   Waiting {delay:.1f}s before retry...")
                    time.sleep(delay)
                    # Exponential backoff
                    delay = min(delay * 2, max_delay)
                    attempt += 1
                    continue
                # Other HTTP errors - re-raise
                raise
            except requests.exceptions.RequestException as e:
                # Check error message for rate limiting
                error_str = str(e).lower()
                if "429" in error_str or "too many requests" in error_str or "rate limit" in error_str:
                    print(f"⚠ Rate limited on attempt {attempt + 1}/{max_retries}: {e}")
                    print(f"   Waiting {delay:.1f}s before retry...")
                    time.sleep(delay)
                    # Exponential backoff
                    delay = min(delay * 2, max_delay)
                    attempt += 1
                    continue
                # Other request errors - re-raise
                raise

        # All retries exhausted
        print(f"✗ Rate limit retries exhausted after {max_retries} attempts")
        return None

    def login(self) -> bool:
        """
        Authenticate with the UniFi controller.

        Returns:
            True if login successful, False otherwise
        """
        login_url = f"https://{self.host}/api/auth/login"
        login_data = {
            "username": self.username,
            "password": self.password,
        }

        def make_login_request():
            response = self.session.post(
                login_url, json=login_data, verify=self.verify_ssl
            )
            response.raise_for_status()
            return response

        try:
            response = self._retry_with_backoff(make_login_request)
            if response is None:
                print("✗ Authentication failed: Rate limit retries exhausted")
                return False

            # Extract CSRF token from response headers
            self.csrf_token = response.headers.get("X-CSRF-Token", "")

            # Update session headers with CSRF token if available
            if self.csrf_token:
                self.session.headers.update({"X-CSRF-Token": self.csrf_token})

            print(f"✓ Successfully authenticated to {self.host}")
            return True

        except requests.exceptions.RequestException as e:
            print(f"✗ Authentication failed: {e}")
            return False

    def _get_endpoint(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """
        Generic method to GET an API endpoint.

        Args:
            endpoint: API endpoint path (without leading slash)

        Returns:
            Response data as dictionary, or None on error
        """
        url = f"https://{self.host}{endpoint}"

        def make_get_request():
            response = self.session.get(url, verify=self.verify_ssl)
            response.raise_for_status()
            return response

        try:
            response = self._retry_with_backoff(make_get_request)
            if response is None:
                return None
            return response.json()
        except requests.exceptions.RequestException:
            return None

    def _put_endpoint(self, endpoint: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Generic method to PUT (update) an API endpoint.

        Args:
            endpoint: API endpoint path (without leading slash)
            data: Data to send in the request body

        Returns:
            Response data as dictionary, or None on error
        """
        url = f"https://{self.host}{endpoint}"

        def make_put_request():
            response = self.session.put(url, json=data, verify=self.verify_ssl)
            response.raise_for_status()
            return response

        try:
            response = self._retry_with_backoff(make_put_request)
            if response is None:
                print(f"✗ Error updating endpoint {endpoint}: Rate limit retries exhausted")
                return None
            
            result = response.json()
            
            # Validate response - check for error indicators
            if isinstance(result, dict):
                # Check for common error indicators in UniFi API responses
                if result.get("meta", {}).get("rc") == "error":
                    error_msg = result.get("meta", {}).get("msg", "Unknown error")
                    print(f"✗ API returned error: {error_msg}")
                    return None
                # Some endpoints return success in meta.rc
                if result.get("meta", {}).get("rc") == "ok":
                    # Extract data if present
                    if "data" in result:
                        return result["data"]
                    return result
            
            return result
        except requests.exceptions.HTTPError as e:
            # Provide more detailed error information
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_body = e.response.json()
                    if isinstance(error_body, dict):
                        api_error = error_body.get("meta", {}).get("msg") or error_body.get("error") or error_body.get("message")
                        if api_error:
                            error_msg = f"{error_msg}\n  API Error: {api_error}"
                        # Show validation errors if present
                        if "errors" in error_body.get("meta", {}):
                            error_msg = f"{error_msg}\n  Validation errors: {error_body['meta']['errors']}"
                except (ValueError, KeyError):
                    # If JSON parsing fails, try to get text
                    try:
                        error_text = e.response.text[:500]  # Limit to first 500 chars
                        if error_text:
                            error_msg = f"{error_msg}\n  Response: {error_text}"
                    except Exception:
                        pass
            
            print(f"✗ Error updating endpoint {endpoint}: {error_msg}")
            
            # Provide context-specific tips based on endpoint type
            if "portforward" in endpoint.lower():
                print("  Tip: For port forwards, check:")
                print("    - Field names: fwd (not fwd_ip), proto (not protocol)")
                print("    - PortForwardOverlaps may indicate a limit on UDP port forwards per port")
            elif "firewall" in endpoint.lower() or "policy" in endpoint.lower():
                print("  Tip: For firewall policies, check:")
                print("    - Action must be uppercase: 'ALLOW', 'BLOCK', or 'REJECT'")
                print("    - Protocol must be lowercase: 'tcp', 'udp', 'all', etc.")
                print("    - Field names and data types match the API schema")
            else:
                print("  Tip: Check field names, data types, and required fields")
            
            return None
        except requests.exceptions.RequestException as e:
            print(f"✗ Error updating endpoint {endpoint}: {e}")
            return None

    def _post_endpoint(self, endpoint: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Generic method to POST (create) an API endpoint.

        Args:
            endpoint: API endpoint path (without leading slash)
            data: Data to send in the request body

        Returns:
            Response data as dictionary, or None on error
        """
        url = f"https://{self.host}{endpoint}"

        def make_post_request():
            response = self.session.post(url, json=data, verify=self.verify_ssl)
            response.raise_for_status()
            return response

        try:
            response = self._retry_with_backoff(make_post_request)
            if response is None:
                print(f"✗ Error creating endpoint {endpoint}: Rate limit retries exhausted")
                return None
            
            result = response.json()
            
            # Check for API-level errors in response
            if isinstance(result, dict):
                if result.get("meta", {}).get("rc") == "error":
                    error_msg = result.get("meta", {}).get("msg", "Unknown error")
                    print(f"✗ API returned error: {error_msg}")
                    # Try to extract more details
                    if "errors" in result.get("meta", {}):
                        print(f"  Details: {result['meta']['errors']}")
                    # Special handling for port forward overlaps
                    if "PortForwardOverlaps" in error_msg or "overlap" in error_msg.lower():
                        print("  Note: Port forward overlap detected.")
                        print("  This may indicate:")
                        print("    - A limit on UDP port forwards per port/protocol combination")
                        print("    - An existing port forward without source restriction")
                        print("    - UniFi API limitation with UDP protocol")
                        print("  Current UDP 41641 port forwards:")
                        existing = self.list_port_forwards()
                        udp_41641 = [r for r in existing if r.get("dst_port") == "41641" and r.get("proto") == "udp"]
                        for r in udp_41641:
                            src = r.get("src", "any")
                            print(f"    - {r.get('name')} (src: {src})")
                        print("  Consider: Firewall rules may be sufficient for access control.")
                    return None
            
            return result
        except requests.exceptions.HTTPError as e:
            # Provide more detailed error information
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_body = e.response.json()
                    if isinstance(error_body, dict):
                        api_error = error_body.get("meta", {}).get("msg") or error_body.get("error") or error_body.get("message")
                        if api_error:
                            error_msg = f"{error_msg}\n  API Error: {api_error}"
                        # Show validation errors if present
                        if "errors" in error_body.get("meta", {}):
                            error_msg = f"{error_msg}\n  Validation errors: {error_body['meta']['errors']}"
                except (ValueError, KeyError):
                    # If JSON parsing fails, try to get text
                    try:
                        error_text = e.response.text[:500]  # Limit to first 500 chars
                        if error_text:
                            error_msg = f"{error_msg}\n  Response: {error_text}"
                    except Exception:
                        pass
            
            print(f"✗ Error creating endpoint {endpoint}: {error_msg}")
            
            # Provide context-specific tips based on endpoint type
            if "portforward" in endpoint.lower():
                print("  Tip: For port forwards, check:")
                print("    - Required fields: name, dst_port, fwd_port, fwd (or fwd_ip)")
                print("    - Protocol must be: tcp, udp, or tcp_udp")
                print("    - PortForwardOverlaps may indicate a limit on UDP port forwards per port")
            elif "firewall" in endpoint.lower() or "policy" in endpoint.lower():
                print("  Tip: For firewall policies, check:")
                print("    - Action must be uppercase: 'ALLOW', 'BLOCK', or 'REJECT'")
                print("    - Protocol must be lowercase: 'tcp', 'udp', 'all', etc.")
                print("    - Field names and data types match the API schema")
            else:
                print("  Tip: Check field names, data types, and required fields")
            
            return None
        except requests.exceptions.RequestException as e:
            print(f"✗ Error creating endpoint {endpoint}: {e}")
            return None

    def _delete_endpoint(self, endpoint: str) -> bool:
        """
        Generic method to DELETE an API endpoint.

        Args:
            endpoint: API endpoint path (without leading slash)

        Returns:
            True if successful, False otherwise
        """
        url = f"https://{self.host}{endpoint}"

        def make_delete_request():
            response = self.session.delete(url, verify=self.verify_ssl)
            response.raise_for_status()
            return response

        try:
            response = self._retry_with_backoff(make_delete_request)
            if response is None:
                print(f"✗ Error deleting endpoint {endpoint}: Rate limit retries exhausted")
                return False
            return True
        except requests.exceptions.RequestException as e:
            print(f"✗ Error deleting endpoint {endpoint}: {e}")
            return False

    def toggle_policy(self, policy_id: str, verify: bool = True) -> bool:
        """
        Toggle a firewall policy enabled/disabled state.
        Uses the simpler toggle endpoint that only requires the enabled field.

        Args:
            policy_id: Policy ID to toggle
            verify: Whether to verify the toggle by re-fetching the policy (default: True)

        Returns:
            True if successful and verified (if verify=True), False otherwise
        """
        # Get current policy to determine new state
        policy = self.get_policy_by_id(policy_id)
        if not policy:
            return False
        
        new_state = not policy.get("enabled", False)
        endpoint = f"/proxy/network/v2/api/site/{self.site}/firewall-policies/{policy_id}"
        result = self._put_endpoint(endpoint, {"enabled": new_state})
        
        if result is None:
            return False
        
        # Verify the toggle by re-fetching the policy
        if verify:
            time.sleep(0.5)
            updated_policy = self.get_policy_by_id(policy_id)
            if not updated_policy:
                return False
            if updated_policy.get("enabled") != new_state:
                return False
        
        return True

    def update_policy(self, policy_id: str, update_data: Dict[str, Any], verify: bool = True) -> bool:
        """
        Update a firewall policy with full policy object.
        
        Uses different endpoints based on what fields are being updated:
        - Individual endpoint (/firewall-policies/{id}): For name/description updates
        - Batch endpoint (/firewall-policies/batch): For other field updates
        
        Args:
            policy_id: Policy ID to update
            update_data: Dictionary with fields to update (merged into full policy)
            verify: Whether to verify the update by re-fetching the policy (default: True)

        Returns:
            True if successful and verified (if verify=True), False otherwise
        """
        # Get current policy to merge updates
        policy = self.get_policy_by_id(policy_id)
        if not policy:
            return False
        
        # Make a deep copy to avoid modifying the original policy object
        policy_copy = copy.deepcopy(policy)
        
        # Check if we're updating name or description
        # These fields require the individual endpoint, not batch
        updating_name_or_desc = "name" in update_data or "description" in update_data
        
        # Merge updates into the copy
        policy_copy.update(update_data)
        
        if updating_name_or_desc:
            # Use individual endpoint for name/description updates
            # This endpoint supports all fields including name/description
            endpoint = f"/proxy/network/v2/api/site/{self.site}/firewall-policies/{policy_id}"
            result = self._put_endpoint(endpoint, policy_copy)
        else:
            # Use batch endpoint for other field updates (more efficient)
            endpoint = f"/proxy/network/v2/api/site/{self.site}/firewall-policies/batch"
            result = self._put_endpoint(endpoint, [policy_copy])
            
            # Batch endpoint returns a list, extract the first item if present
            if isinstance(result, list) and len(result) > 0:
                result = result[0]
        
        if result is None:
            return False
        
        # Verify the update by re-fetching the policy
        if verify:
            # Small delay to allow API to process the update
            time.sleep(0.5)
            
            updated_policy = self.get_policy_by_id(policy_id)
            if not updated_policy:
                return False
            
            # Track which fields updated successfully
            updated_fields = []
            failed_fields = []
            
            # Verify that the updated fields match what we sent
            for key, expected_value in update_data.items():
                actual_value = updated_policy.get(key)
                field_updated = False
                
                if actual_value == expected_value:
                    field_updated = True
                else:
                    # Special handling for nested dicts (like source/destination)
                    if isinstance(expected_value, dict) and isinstance(actual_value, dict):
                        # For nested dicts, check if all expected keys match
                        if all(actual_value.get(k) == v for k, v in expected_value.items()):
                            field_updated = True
                    else:
                        # For non-dict values, handle empty string vs None
                        if expected_value == "" and actual_value is None:
                            # API might convert empty strings to None
                            field_updated = True
                        elif actual_value == "" and expected_value is None:
                            # Or vice versa
                            field_updated = True
                
                if field_updated:
                    updated_fields.append(key)
                else:
                    failed_fields.append(key)
            
            # If some fields failed to update, report it
            if failed_fields and not updated_fields:
                # All fields failed - this is a real failure
                return False
            elif failed_fields:
                # Some fields failed - log a warning
                print(f"⚠ Some fields may not have updated: {', '.join(failed_fields)}")
                print(f"  Successfully updated: {', '.join(updated_fields) if updated_fields else 'none'}")
                # Still return True if we got a successful API response and some fields updated
                return len(updated_fields) > 0
            
            return True
        
        return True

    def create_policy(self, policy_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Create a new firewall policy.

        Args:
            policy_data: Dictionary with complete policy configuration
                         Will be validated and normalized before sending to API.

        Returns:
            Created policy dictionary, or None on error
        """
        # Validate and normalize policy data
        is_valid, error_msg = validate_policy_data(policy_data)
        if not is_valid:
            print(f"✗ Policy validation failed: {error_msg}")
            return None
        
        endpoint = f"/proxy/network/v2/api/site/{self.site}/firewall-policies"
        return self._post_endpoint(endpoint, policy_data)

    def delete_policy(self, policy_id: str) -> bool:
        """
        Delete a firewall policy by ID.

        Args:
            policy_id: Policy ID to delete

        Returns:
            True if successful, False otherwise
        """
        endpoint = f"/proxy/network/v2/api/site/{self.site}/firewall-policies/{policy_id}"
        return self._delete_endpoint(endpoint)

    def list_firewall_policies(self) -> list[Dict[str, Any]]:
        """
        List all firewall policies (zone-based firewall rules).
        
        Uses V2 API endpoint discovered from unifi-network-mcp source code:
        /proxy/network/v2/api/site/{site}/firewall-policies

        Returns:
            List of firewall policy dictionaries
        """
        endpoint = f"/proxy/network/v2/api/site/{self.site}/firewall-policies"
        data = self._get_endpoint(endpoint)

        if data is None:
            return []

        if isinstance(data, dict) and "data" in data:
            return data["data"]
        elif isinstance(data, list):
            return data
        else:
            return []

    def get_policy_by_id(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific firewall policy by ID.

        Args:
            policy_id: Policy ID

        Returns:
            Policy dictionary or None if not found
        """
        policies = self.list_firewall_policies()
        return next((p for p in policies if p.get("_id") == policy_id), None)

    def list_firewall_groups(self) -> list[Dict[str, Any]]:
        """
        List firewall groups (IP/port groups used in rules).

        Returns:
            List of firewall group dictionaries
        """
        endpoint = f"/proxy/network/api/s/{self.site}/rest/firewallgroup"
        data = self._get_endpoint(endpoint)

        if data is None:
            return []

        if isinstance(data, dict) and "data" in data:
            return data["data"]
        elif isinstance(data, list):
            return data
        else:
            return []

    def create_firewall_group(
        self, name: str, group_type: str, members: list[str]
    ) -> Optional[Dict[str, Any]]:
        """
        Create a new firewall group.

        Args:
            name: Group name
            group_type: Group type (e.g., "address-group", "port-group")
            members: List of members (IP addresses, CIDRs, or ports)

        Returns:
            Created group dictionary, or None on error
        """
        endpoint = f"/proxy/network/api/s/{self.site}/rest/firewallgroup"
        data = {
            "name": name,
            "group_type": group_type,
            "group_members": members,
        }
        return self._post_endpoint(endpoint, data)

    def update_firewall_group(self, group_id: str, members: list[str], verify: bool = True) -> bool:
        """
        Update a firewall group's members.

        Args:
            group_id: Group ID to update
            members: New list of members (IP addresses, CIDRs, or ports)
            verify: Whether to verify the update by re-fetching the group (default: True)

        Returns:
            True if successful and verified (if verify=True), False otherwise
        """
        endpoint = f"/proxy/network/api/s/{self.site}/rest/firewallgroup/{group_id}"
        data = {"group_members": members}
        result = self._put_endpoint(endpoint, data)
        
        if result is None:
            return False
        
        # Verify the update by re-fetching the group
        if verify:
            time.sleep(0.5)
            groups = self.list_firewall_groups()
            updated_group = next((g for g in groups if g.get("_id") == group_id), None)
            if not updated_group:
                return False
            # Compare members (as sets to ignore order)
            updated_members = set(updated_group.get("group_members", []))
            expected_members = set(members)
            if updated_members != expected_members:
                return False
        
        return True

    def delete_firewall_group(self, group_id: str) -> bool:
        """
        Delete a firewall group by ID.

        Args:
            group_id: Group ID to delete

        Returns:
            True if successful, False otherwise
        """
        endpoint = f"/proxy/network/api/s/{self.site}/rest/firewallgroup/{group_id}"
        return self._delete_endpoint(endpoint)

    def list_port_forwards(self) -> list[Dict[str, Any]]:
        """
        List all port forwarding rules.

        Returns:
            List of port forwarding rule dictionaries
        """
        endpoint = f"/proxy/network/api/s/{self.site}/rest/portforward"
        data = self._get_endpoint(endpoint)

        if data is None:
            return []

        if isinstance(data, dict) and "data" in data:
            return data["data"]
        elif isinstance(data, list):
            return data
        else:
            return []

    def get_port_forward_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific port forwarding rule by ID.

        Args:
            rule_id: Port forward rule ID

        Returns:
            Port forward rule dictionary or None if not found
        """
        rules = self.list_port_forwards()
        return next((r for r in rules if r.get("_id") == rule_id), None)

    def create_port_forward(self, rule_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Create a new port forwarding rule.

        Args:
            rule_data: Dictionary with port forward configuration:
                      - name (str): Rule name
                      - dst_port (str): External/destination port
                      - fwd_port (str): Internal port to forward to
                      - fwd_ip (str): Internal IP address to forward to
                      - proto (str, optional): Protocol (tcp, udp, tcp_udp)
                      - enabled (bool, optional): Whether rule is enabled
                      - src (str, optional): Source IP/CIDR to match
                      - log (bool, optional): Whether to log matches

        Returns:
            Created rule dictionary, or None on error
        """
        # Normalize field names - API expects 'fwd' not 'fwd_ip'
        if "fwd_ip" in rule_data and "fwd" not in rule_data:
            rule_data["fwd"] = rule_data["fwd_ip"]
        
        # Set default fields to match existing port forward structure
        if "pfwd_interface" not in rule_data:
            rule_data["pfwd_interface"] = "wan"
        if "destination_ip" not in rule_data:
            rule_data["destination_ip"] = "any"
        if "destination_ips" not in rule_data:
            rule_data["destination_ips"] = []
        
        # If source IP is provided, automatically set source limiting fields
        if "src" in rule_data and rule_data["src"]:
            rule_data["src_limiting_enabled"] = True
            rule_data["src_limiting_type"] = "ip"
            if "log" not in rule_data:
                rule_data["log"] = True
        
        endpoint = f"/proxy/network/api/s/{self.site}/rest/portforward"
        
        result = self._post_endpoint(endpoint, rule_data)

        if result and isinstance(result, dict) and "data" in result:
            data = result["data"]
            if isinstance(data, list) and len(data) > 0:
                return data[0]
        elif result and isinstance(result, dict) and result.get("_id"):
            return result

        return result

    def update_port_forward(self, rule_id: str, update_data: Dict[str, Any], verify: bool = True) -> bool:
        """
        Update a port forwarding rule.

        Args:
            rule_id: Rule ID to update
            update_data: Dictionary with fields to update (merged into full rule)
            verify: Whether to verify the update by re-fetching the rule (default: True)

        Returns:
            True if successful and verified (if verify=True), False otherwise
        """
        # Get current rule to merge updates
        rule = self.get_port_forward_by_id(rule_id)
        if not rule:
            return False

        # Make a deep copy to avoid modifying the original rule object
        rule_copy = copy.deepcopy(rule)
        
        # Merge updates into the copy
        rule_copy.update(update_data)

        endpoint = f"/proxy/network/api/s/{self.site}/rest/portforward/{rule_id}"
        result = self._put_endpoint(endpoint, rule_copy)
        
        if result is None:
            return False
        
        # Verify the update by re-fetching the rule
        if verify:
            time.sleep(0.5)
            updated_rule = self.get_port_forward_by_id(rule_id)
            if not updated_rule:
                return False
            # Verify that the updated fields match what we sent
            for key, expected_value in update_data.items():
                actual_value = updated_rule.get(key)
                if actual_value != expected_value:
                    # Special handling for nested dicts
                    if isinstance(expected_value, dict) and isinstance(actual_value, dict):
                        # For nested dicts, check if all expected keys match
                        if not all(actual_value.get(k) == v for k, v in expected_value.items()):
                            return False
                    else:
                        # For non-dict values, handle empty string vs None
                        if expected_value == "" and actual_value is None:
                            # API might convert empty strings to None
                            continue
                        if actual_value == "" and expected_value is None:
                            # Or vice versa
                            continue
                        return False
        
        return True

    def delete_port_forward(self, rule_id: str) -> bool:
        """
        Delete a port forwarding rule by ID.

        Args:
            rule_id: Rule ID to delete

        Returns:
            True if successful, False otherwise
        """
        endpoint = f"/proxy/network/api/s/{self.site}/rest/portforward/{rule_id}"
        return self._delete_endpoint(endpoint)

    def toggle_port_forward(self, rule_id: str) -> bool:
        """
        Toggle a port forwarding rule enabled/disabled state.

        Args:
            rule_id: Rule ID to toggle

        Returns:
            True if successful, False otherwise
        """
        rule = self.get_port_forward_by_id(rule_id)
        if not rule:
            return False

        new_state = not rule.get("enabled", False)
        return self.update_port_forward(rule_id, {"enabled": new_state})

    def list_static_routes(self) -> list[Dict[str, Any]]:
        """
        List all static routes.

        Returns:
            List of static route dictionaries
        """
        endpoint = f"/proxy/network/api/s/{self.site}/rest/routing"
        data = self._get_endpoint(endpoint)

        if data is None:
            return []

        if isinstance(data, dict) and "data" in data:
            return data["data"]
        elif isinstance(data, list):
            return data
        else:
            return []

    def get_static_route_by_id(self, route_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific static route by ID.

        Args:
            route_id: Static route ID

        Returns:
            Static route dictionary or None if not found
        """
        routes = self.list_static_routes()
        return next((r for r in routes if r.get("_id") == route_id), None)

    def create_static_route(
        self,
        name: str,
        network: str,
        nexthop: str,
        distance: int = 1,
        enabled: bool = True,
        route_type: str = "nexthop-route",
    ) -> Optional[Dict[str, Any]]:
        """
        Create a new static route.

        Args:
            name: Route name/description
            network: Destination network in CIDR format (e.g., "10.0.0.0/24")
            nexthop: Next-hop IP address
            distance: Administrative distance (default: 1)
            enabled: Whether route is enabled (default: True)
            route_type: Route type (default: "nexthop-route")

        Returns:
            Created route dictionary, or None on error
        """
        endpoint = f"/proxy/network/api/s/{self.site}/rest/routing"
        data = {
            "name": name,
            "static-route_network": network,
            "static-route_nexthop": nexthop,
            "static-route_distance": distance,
            "enabled": enabled,
            "type": route_type,
        }
        result = self._post_endpoint(endpoint, data)

        if result and isinstance(result, dict) and "data" in result:
            data_list = result["data"]
            if isinstance(data_list, list) and len(data_list) > 0:
                return data_list[0]
        elif result and isinstance(result, dict) and result.get("_id"):
            return result
        elif result and isinstance(result, list) and len(result) > 0:
            return result[0]

        return result

    def update_static_route(self, route_id: str, update_data: Dict[str, Any], verify: bool = True) -> bool:
        """
        Update a static route.

        Args:
            route_id: Route ID to update
            update_data: Dictionary with fields to update (merged into full route)
            verify: Whether to verify the update by re-fetching the route (default: True)

        Returns:
            True if successful and verified (if verify=True), False otherwise
        """
        # Get current route to merge updates
        route = self.get_static_route_by_id(route_id)
        if not route:
            return False

        # Make a deep copy to avoid modifying the original route object
        route_copy = copy.deepcopy(route)
        
        # Merge updates into the copy
        route_copy.update(update_data)

        endpoint = f"/proxy/network/api/s/{self.site}/rest/routing/{route_id}"
        result = self._put_endpoint(endpoint, route_copy)
        
        if result is None:
            return False
        
        # Verify the update by re-fetching the route
        if verify:
            time.sleep(0.5)
            updated_route = self.get_static_route_by_id(route_id)
            if not updated_route:
                return False
            # Verify that the updated fields match what we sent
            for key, expected_value in update_data.items():
                actual_value = updated_route.get(key)
                if actual_value != expected_value:
                    # Special handling for nested dicts
                    if isinstance(expected_value, dict) and isinstance(actual_value, dict):
                        # For nested dicts, check if all expected keys match
                        if not all(actual_value.get(k) == v for k, v in expected_value.items()):
                            return False
                    else:
                        # For non-dict values, handle empty string vs None
                        if expected_value == "" and actual_value is None:
                            # API might convert empty strings to None
                            continue
                        if actual_value == "" and expected_value is None:
                            # Or vice versa
                            continue
                        return False
        
        return True

    def delete_static_route(self, route_id: str) -> bool:
        """
        Delete a static route by ID.

        Args:
            route_id: Route ID to delete

        Returns:
            True if successful, False otherwise
        """
        endpoint = f"/proxy/network/api/s/{self.site}/rest/routing/{route_id}"
        return self._delete_endpoint(endpoint)

    # -------------------------------------------------------------------------
    # DNS Records (gateway-level static DNS records, Policy Table → DNS Records)
    # -------------------------------------------------------------------------

    def list_static_dns_records(self) -> list[Dict[str, Any]]:
        """
        List all static DNS records.

        These are the records in Network → Settings → Policy Table → DNS Records
        (e.g. scrypted.spaceterran.com → 192.168.52.77).

        Returns:
            List of static DNS record dictionaries
        """
        endpoint = f"/proxy/network/v2/api/site/{self.site}/static-dns"
        data = self._get_endpoint(endpoint)

        if data is None:
            return []

        if isinstance(data, dict) and "data" in data:
            return data["data"]
        elif isinstance(data, list):
            return data
        else:
            return []

    def get_static_dns_record_by_id(self, record_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific static DNS record by ID.

        Args:
            record_id: DNS record ID

        Returns:
            DNS record dictionary or None if not found
        """
        records = self.list_static_dns_records()
        return next((r for r in records if r.get("_id") == record_id), None)

    def get_static_dns_record_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get a static DNS record by exact or partial domain match (case-insensitive).

        Args:
            domain: Domain name to search for

        Returns:
            DNS record dictionary or None if not found
        """
        domain = (domain or "").strip().lower()
        if not domain:
            return None
        records = self.list_static_dns_records()
        for rec in records:
            d = (rec.get("key") or "").lower()
            if d == domain or domain in d:
                return rec
        return None

    def create_static_dns_record(self, record_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Create a new static DNS record.

        Args:
            record_data: Dictionary with DNS record configuration:
                        - key (str): Domain name (e.g. "scrypted.spaceterran.com")
                        - value (str): IP address or hostname
                        - record_type (str, optional): "A", "AAAA", "CNAME", "MX", "SRV", "TXT"
                        - ttl (int, optional): TTL in seconds (0 = Auto)
                        - enabled (bool, optional): Whether the record is enabled
                        - priority (int, optional): Priority for MX/SRV records
                        - weight (int, optional): Weight for SRV records
                        - port (int, optional): Port for SRV records

        Returns:
            Created record dictionary, or None on error
        """
        # Set defaults
        if "record_type" not in record_data:
            record_data["record_type"] = "A"
        if "ttl" not in record_data:
            record_data["ttl"] = 0
        if "enabled" not in record_data:
            record_data["enabled"] = True
        if "priority" not in record_data:
            record_data["priority"] = 0
        if "weight" not in record_data:
            record_data["weight"] = 0
        if "port" not in record_data:
            record_data["port"] = 0

        endpoint = f"/proxy/network/v2/api/site/{self.site}/static-dns"
        result = self._post_endpoint(endpoint, record_data)

        if result and isinstance(result, dict) and "data" in result:
            data = result["data"]
            if isinstance(data, list) and len(data) > 0:
                return data[0]
        elif result and isinstance(result, dict) and result.get("_id"):
            return result

        return result

    def update_static_dns_record(self, record_id: str, update_data: Dict[str, Any], verify: bool = True) -> bool:
        """
        Update a static DNS record.

        Args:
            record_id: Record ID to update
            update_data: Dictionary with fields to update (merged into full record)
            verify: Whether to verify the update by re-fetching the record (default: True)

        Returns:
            True if successful and verified (if verify=True), False otherwise
        """
        # Get current record to merge updates
        record = self.get_static_dns_record_by_id(record_id)
        if not record:
            return False

        # Make a deep copy to avoid modifying the original record object
        record_copy = copy.deepcopy(record)
        
        # Merge updates into the copy
        record_copy.update(update_data)

        endpoint = f"/proxy/network/v2/api/site/{self.site}/static-dns/{record_id}"
        result = self._put_endpoint(endpoint, record_copy)
        
        if result is None:
            return False
        
        # Verify the update by re-fetching the record
        if verify:
            time.sleep(0.5)
            updated_record = self.get_static_dns_record_by_id(record_id)
            if not updated_record:
                return False
            # Verify that the updated fields match what we sent
            for key, expected_value in update_data.items():
                actual_value = updated_record.get(key)
                if actual_value != expected_value:
                    # For non-dict values, handle empty string vs None
                    if expected_value == "" and actual_value is None:
                        continue
                    if actual_value == "" and expected_value is None:
                        continue
                    return False
        
        return True

    def delete_static_dns_record(self, record_id: str) -> bool:
        """
        Delete a static DNS record by ID.

        Args:
            record_id: Record ID to delete

        Returns:
            True if successful, False otherwise
        """
        endpoint = f"/proxy/network/v2/api/site/{self.site}/static-dns/{record_id}"
        return self._delete_endpoint(endpoint)

    def toggle_static_dns_record(self, record_id: str) -> bool:
        """
        Toggle a static DNS record enabled/disabled state.

        Args:
            record_id: Record ID to toggle

        Returns:
            True if successful, False otherwise
        """
        record = self.get_static_dns_record_by_id(record_id)
        if not record:
            return False

        new_state = not record.get("enabled", False)
        return self.update_static_dns_record(record_id, {"enabled": new_state})

    # Aliases for backward compatibility with existing scripts
    def list_policy_dns_records(self, domain_filter: Optional[str] = None) -> list[Dict[str, Any]]:
        """List DNS records with optional domain filter. Returns normalized format for backward compatibility."""
        records = self.list_static_dns_records()
        result = []
        for r in records:
            domain = r.get("key", "")
            if domain_filter and domain_filter.lower() not in domain.lower():
                continue
            result.append({
                "_id": r.get("_id"),
                "domain": domain,
                "type": r.get("record_type", "A"),
                "ip_or_hostname": r.get("value", ""),
                "ttl": r.get("ttl") if r.get("ttl") else None,
                "enabled": r.get("enabled", True),
                "raw": r,
            })
        return result

    def get_policy_dns_record_by_id(self, record_id: str) -> Optional[Dict[str, Any]]:
        """Get DNS record by ID. Returns normalized format for backward compatibility."""
        rec = self.get_static_dns_record_by_id(record_id)
        if rec:
            return {
                "_id": rec.get("_id"),
                "domain": rec.get("key", ""),
                "type": rec.get("record_type", "A"),
                "ip_or_hostname": rec.get("value", ""),
                "ttl": rec.get("ttl") if rec.get("ttl") else None,
                "enabled": rec.get("enabled", True),
                "raw": rec,
            }
        return None

    def get_policy_dns_record_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get DNS record by domain. Returns normalized format for backward compatibility."""
        rec = self.get_static_dns_record_by_domain(domain)
        if rec:
            return {
                "_id": rec.get("_id"),
                "domain": rec.get("key", ""),
                "type": rec.get("record_type", "A"),
                "ip_or_hostname": rec.get("value", ""),
                "ttl": rec.get("ttl") if rec.get("ttl") else None,
                "enabled": rec.get("enabled", True),
                "raw": rec,
            }
        return None

    def create_policy_dns_record(
        self,
        domain: str,
        ip_or_hostname: str,
        record_type: str = "A",
        ttl: Optional[int] = None,
        enabled: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """Create DNS record. Backward compatible wrapper."""
        return self.create_static_dns_record({
            "key": domain,
            "value": ip_or_hostname,
            "record_type": record_type,
            "ttl": ttl if ttl is not None else 0,
            "enabled": enabled,
        })

    def update_policy_dns_record(
        self,
        record_id: str,
        domain: Optional[str] = None,
        ip_or_hostname: Optional[str] = None,
        record_type: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> bool:
        """Update DNS record. Backward compatible wrapper."""
        update_data = {}
        if domain is not None:
            update_data["key"] = domain
        if ip_or_hostname is not None:
            update_data["value"] = ip_or_hostname
        if record_type is not None:
            update_data["record_type"] = record_type
        if enabled is not None:
            update_data["enabled"] = enabled
        if not update_data:
            return True
        return self.update_static_dns_record(record_id, update_data)

    def delete_policy_dns_record(self, record_id: str) -> bool:
        """Delete DNS record. Backward compatible wrapper."""
        return self.delete_static_dns_record(record_id)

    def get_network_configs(self) -> list[Dict[str, Any]]:
        """
        Get network configurations which contain zone assignments.

        Returns:
            List of network configuration dictionaries
        """
        endpoint = f"/proxy/network/api/s/{self.site}/rest/networkconf"
        data = self._get_endpoint(endpoint)

        if data is None:
            return []

        if isinstance(data, dict) and "data" in data:
            return data["data"]
        elif isinstance(data, list):
            return data
        else:
            return []

    def format_policy(self, policy: Dict[str, Any]) -> str:
        """
        Format a firewall policy for display.
        Handles V2 API policies with nested source/destination objects.

        Args:
            policy: Firewall policy dictionary

        Returns:
            Formatted string representation
        """
        policy_id = policy.get("_id", policy.get("id", "N/A"))
        name = policy.get("name", policy.get("description", "Unnamed"))
        enabled = "✓ Enabled" if policy.get("enabled", True) else "✗ Disabled"
        action = policy.get("action", policy.get("type", "unknown")).upper()
        protocol = policy.get("protocol", "any")
        index = policy.get("index", policy.get("rule_index"))

        # V2 API structure (zone-based firewall policies)
        source = policy.get("source", {})
        destination = policy.get("destination", {})
        
        if isinstance(source, dict):
            src_zone_id = source.get("zone_id", "")
            src_matching_target = source.get("matching_target", "ANY")
            src_ips = source.get("ips", [])
            src_port = source.get("port", "")
        else:
            src_zone_id = ""
            src_matching_target = "ANY"
            src_ips = []
            src_port = ""
        
        if isinstance(destination, dict):
            dst_zone_id = destination.get("zone_id", "")
            dst_matching_target = destination.get("matching_target", "ANY")
            dst_ips = destination.get("ips", [])
            dst_port = destination.get("port", "")
        else:
            dst_zone_id = ""
            dst_matching_target = "ANY"
            dst_ips = []
            dst_port = ""

        # Format addresses
        src_address = ", ".join(src_ips) if src_ips else (src_matching_target if src_matching_target != "ANY" else "Any")
        dst_address = ", ".join(dst_ips) if dst_ips else (dst_matching_target if dst_matching_target != "ANY" else "Any")

        lines = [
            f"  ID: {policy_id}",
            f"  Name: {name}",
            f"  Status: {enabled}",
            f"  Action: {action}",
        ]

        if index is not None:
            lines.append(f"  Index: {index}")

        if protocol and protocol.lower() not in ["any", "all"]:
            lines.append(f"  Protocol: {protocol.upper()}")

        if src_zone_id:
            lines.append(f"  Source Zone ID: {src_zone_id}")
        if src_address and src_address not in ["any", "Any", "ANY"]:
            lines.append(f"  Source: {src_address}")
        if src_port and src_port not in ["any", "Any", "ANY"]:
            lines.append(f"  Source Port: {src_port}")

        if dst_zone_id:
            lines.append(f"  Destination Zone ID: {dst_zone_id}")
        if dst_address and dst_address not in ["any", "Any", "ANY"]:
            lines.append(f"  Destination: {dst_address}")
        if dst_port and dst_port not in ["any", "Any", "ANY"]:
            lines.append(f"  Destination Port: {dst_port}")

        return "\n".join(lines)


def get_client_from_env() -> UniFiFirewallClient:
    """
    Create a UniFiFirewallClient from environment variables.
    
    Supports both plaintext (UNIFI_PASSWORD) and encrypted passwords.
    If UNIFI_PASSWORD is not set, attempts to load from .env.password.encrypted.

    Returns:
        Configured UniFiFirewallClient instance
    """
    from password_manager import load_encrypted_password
    
    host = os.getenv("UNIFI_HOST", "192.168.53.1")
    username = os.getenv("UNIFI_USERNAME")
    password = os.getenv("UNIFI_PASSWORD")
    site = os.getenv("UNIFI_SITE", "default")
    verify_ssl = os.getenv("UNIFI_VERIFY_SSL", "false").lower() == "true"

    # If password not in env, try to load from encrypted file
    if not password:
        password = load_encrypted_password()
    
    if not username or not password:
        raise ValueError(
            "UNIFI_USERNAME and UNIFI_PASSWORD must be set. "
            "Either set UNIFI_PASSWORD in .env or use encrypted password file."
        )

    return UniFiFirewallClient(host, username, password, site, verify_ssl)
