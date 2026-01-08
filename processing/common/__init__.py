"""Common operations shared across device processors."""
from .vrf import get_or_create_vrf
from .device_type import get_or_create_device_type, create_interface_templates
from .ip_address import add_primary_ip_to_device
from .mac_address import add_mac_address_to_interface

__all__ = [
    'get_or_create_vrf',
    'get_or_create_device_type',
    'create_interface_templates',
    'add_primary_ip_to_device',
    'add_mac_address_to_interface',
]

