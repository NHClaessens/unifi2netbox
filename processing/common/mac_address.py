"""MAC address operations."""
from logger import logger
from context import AppContext
import pynetbox


def add_mac_address_to_interface(
    device_mac: str, 
    interface: pynetbox.core.response.Record, 
    device_name: str, 
    ctx: AppContext, 
    set_as_primary: bool = False
    ) -> bool:
    """
    Add MAC address to an interface in NetBox.
    
    Args:
        device_mac: MAC address string
        interface_id: NetBox interface ID
        device_name: Device name for logging
        ctx: Application context
        set_as_primary: Whether to set the MAC address as the primary MAC address for the device
    Returns:
        True if successful, False otherwise
    """
    if not device_mac:
        logger.debug(f"No MAC address for device {device_name}. Skipping MAC assignment.")
        return False
    
    try:
        # Check if MAC address already exists
        existing_mac = ctx.nb.dcim.mac_addresses.get(mac_address=device_mac)
        if existing_mac:
            logger.debug(f"MAC address {device_mac} already exists in NetBox.")
            return True
        
        # Create MAC address
        mac_address = ctx.nb.dcim.mac_addresses.create({
            "mac_address": device_mac,
            "assigned_object_id": interface.id,
            "assigned_object_type": "dcim.interface",
        })
        if mac_address:
            logger.info(f"MAC address {device_mac} with ID {mac_address.id} successfully added to NetBox.")
            if set_as_primary:
                interface.primary_mac_address = mac_address.id
                interface.save()
                logger.info(f"MAC address {device_mac} with ID {mac_address.id} set as primary MAC address for device {device_name}.")
            return True
    except pynetbox.core.query.RequestError as e:
        logger.exception(f"Failed to create MAC address {device_mac} for device {device_name}: {e}")
        return False
    
    return False

