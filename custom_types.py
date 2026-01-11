"""
Type definitions for UniFi and NetBox API dictionaries.

These TypedDict classes define the structure of dictionaries returned by the APIs,
similar to TypeScript interfaces. They provide type hints without requiring class instantiation.
"""
from enum import StrEnum
from typing import TypedDict, List, Optional


# UniFi Device Types
class UniFiLastConnection(TypedDict, total=False):
    """Structure of last_connection in UniFi port data."""
    mac: str
    last_seen: int


class UniFiPort(TypedDict, total=False):
    """Structure of a port in UniFi device port_table."""
    port_idx: int
    media: str
    port_poe: bool
    speed_caps: int
    last_connection: UniFiLastConnection
    op_mode: str
    forward: str
    is_uplink: bool
    up: bool
    uptime: int
    autoneg: bool
    enable: bool
    full_duplex: bool
    speed: int
    jumbo: bool
    flowctrl_tx: bool
    flowctrl_rx: bool
    tx_bytes: int
    tx_broadcast: int
    tx_multicast: int
    tx_packets: int
    tx_errors: int
    tx_dropped: int
    rx_bytes: int
    rx_broadcast: int
    rx_multicast: int
    rx_packets: int
    rx_errors: int
    rx_dropped: int
    stp_state: str
    stp_pathcost: int
    tx_bytes_r: float
    rx_bytes_r: float
    bytes_r: float
    custom_anomalies: int
    name: str
    enabled: bool
    masked: bool
    aggregated_by: bool


class UniFiDevice(TypedDict, total=False):
    """Structure of a device dictionary from UniFi API."""
    name: str
    model: str
    mac: str
    ip: str
    serial: str
    port_table: List[UniFiPort]
    is_access_point: Optional[str]  # Can be "true", "false", or None


# UniFi Client Device Types
class UniFiClientDevice(TypedDict, total=False):
    """Structure of a client device from UniFi API."""
    site_id: str
    ap_mac: str
    assoc_time: int
    latest_assoc_time: int
    oui: str
    user_id: str
    last_uplink_name: str
    last_ip: str
    first_seen: int
    last_seen: int
    is_guest: bool
    disconnect_timestamp: int
    last_radio: str
    is_wired: bool
    usergroup_id: str
    last_uplink_mac: str
    last_connection_network_name: str
    mac: str
    last_connection_network_id: str
    noted: bool
    name: str
    _id: str
    network_members_group_ids: List[str]
    wlanconf_id: str
    _uptime_by_uap: int
    _last_seen_by_uap: int
    _is_guest_by_uap: bool
    ip: str
    channel: int
    channelWidth: int
    radio: str
    radio_name: str
    essid: str
    bssid: str
    powersave_enabled: bool
    is_11r: bool
    user_group_id_computed: str
    anomalies: int
    anon_client_id: str
    ccq: int
    dhcpend_time: int
    idletime: int
    noise: int
    nss: int
    rx_rate: int
    rssi: int
    satisfaction_now: int
    satisfaction_real: int


# NetBox Types
class NetBoxDeviceData(TypedDict, total=False):
    """Structure of device data dictionary for NetBox API creation."""
    name: str
    device_type: int
    tenant: int
    site: int
    serial: str
    role: Optional[int]
    device_role: Optional[int]


class NetBoxIPAddressData(TypedDict, total=False):
    """Structure of IP address data dictionary for NetBox API creation."""
    assigned_object_id: int
    assigned_object_type: str
    address: str
    vrf_id: int
    tenant_id: int
    status: str

class Roles(StrEnum):
    WIRELESS = 'WIRELESS'
    LAN = 'LAN'
    CLIENT_WIRED = 'CLIENT_WIRED'
    CLIENT_WIRELESS = 'CLIENT_WIRELESS'

# Choices can be found here: https://github.com/netbox-community/netbox/blob/main/netbox/dcim/choices.py
SPEED_MAP = {
    "GE": "1000base-t",
    "2P5GE": "2.5gbase-t",
}

MAX_SPEED_MAP = {
    1000: "1000base-t",
    2500: "2.5gbase-t",
    5000: "5gbase-t",
    10000: "10gbase-t",
    25000: "25gbase-t",
    50000: "50gbase-t",
    100000: "100gbase-t",
    250000: "250gbase-t",
    500000: "500gbase-t",
    1000000: "1000gbase-t",
}

# Map radio type to WiFi standard
# "ng" = 2.4 GHz (typically 802.11n)
# "na" = 5 GHz (typically 802.11ac)
# "ax" = 6 GHz (802.11ax)
RADIO_TYPE_MAP = {
    "ng": "ieee802.11n",  # 2.4 GHz
    "na": "ieee802.11ac",  # 5 GHz
    "ax": "ieee802.11ax",  # 6 GHz
}