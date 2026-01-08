"""MAC address operations."""
from logger import logger
from context import AppContext
import pynetbox


def add_mac_address_to_interface(device_mac: str, interface_id: int, 
                                 device_name: str, ctx: AppContext) -> bool:
    """
    Add MAC address to an interface in NetBox.
    
    Args:
        device_mac: MAC address string
        interface_id: NetBox interface ID
        device_name: Device name for logging
        ctx: Application context
        
    Returns:
        True if successful, False otherwise
    """
    if not device_mac:
        logger.debug(f"No MAC address for device {device_name}. Skipping MAC assignment.")
        return False
    
    try:
        # Check if MAC address already exists
        existing_mac = ctx.nb.ipam.mac_addresses.get(address=device_mac)
        if existing_mac:
            logger.debug(f"MAC address {device_mac} already exists in NetBox.")
            return True
        
        # Create MAC address
        mac_address = ctx.nb.ipam.mac_addresses.create({
            "address": device_mac,
            "assigned_object_id": interface_id,
            "assigned_object_type": "dcim.interface",
        })
        if mac_address:
            logger.info(f"MAC address {device_mac} with ID {mac_address.id} successfully added to NetBox.")
            return True
    except pynetbox.core.query.RequestError as e:
        logger.exception(f"Failed to create MAC address {device_mac} for device {device_name}: {e}")
        return False
    
    return False

