"""Validasi IPv4/CIDR dan whitelist sebelum perubahan kebijakan firewall."""

import ipaddress
from typing import Union

def is_valid_ipv4(ip: str) -> bool:
    """Check if the provided string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_cidr(cidr: str) -> bool:
    """Check if the provided string is a valid IPv4 CIDR notation."""
    try:
        ipaddress.IPv4Network(cidr, strict=False)
        return True
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False

def is_valid_ip_or_cidr(value: str) -> bool:
    """Check if the provided string is either a valid IPv4 address or CIDR."""
    return is_valid_ipv4(value) or is_valid_cidr(value)

def sanitize_string(value: str, max_length: int = 255) -> str:
    """Strip whitespace and truncate a string to the specified maximum length."""
    if not value:
        return ""
    sanitized = str(value).strip()
    if len(sanitized) > max_length:
        return sanitized[:max_length]
    return sanitized

def is_ip_in_whitelist(ip: str, whitelist: str) -> bool:
    """
    Check if a specific IP is included in a comma-separated whitelist.
    The whitelist can contain both exact IP addresses and CIDR notations.
    """
    if not ip or not whitelist:
        return False

    try:
        ip_obj = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return False

    allowed_entries = [entry.strip() for entry in whitelist.split(',') if entry.strip()]

    for entry in allowed_entries:
        try:
            if '/' in entry:
                network = ipaddress.IPv4Network(entry, strict=False)
                if ip_obj in network:
                    return True
            else:
                allowed_ip = ipaddress.IPv4Address(entry)
                if ip_obj == allowed_ip:
                    return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            continue

    return False
