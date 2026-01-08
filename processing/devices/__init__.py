"""Device processors for different device types."""
from .wired import process_wired_device
from .wireless import process_wireless_device
from .client import process_client_device

__all__ = [
    'process_wired_device',
    'process_wireless_device',
    'process_client_device',
]

