"""Base device processing functionality."""
from logger import logger
from context import AppContext
from unifi.sites import Sites
from unifi.unifi import Unifi
from util import get_postable_fields
import pynetbox
from processing.common import (
    get_or_create_device_type,
    create_interface_templates,
    add_primary_ip_to_device,
    add_mac_address_to_interface,
)


def create_netbox_device(device: dict, device_type_id: int, device_role_id: int, 
                        site: Sites, ctx: AppContext) -> pynetbox.core.response.Record | None:
    """
    Create a NetBox device.
    
    Args:
        device: UniFi device dictionary
        device_type_id: NetBox device type ID
        device_role_id: NetBox device role ID
        site: NetBox site object
        ctx: Application context
        
    Returns:
        NetBox device record or None if creation failed
    """
    # Check for existing device
    logger.debug(f"Checking if device already exists: {device['name']} (serial: {device.get('serial')})")
    if device.get("serial") and ctx.nb.dcim.devices.get(site_id=site.id, serial=device["serial"]):
        logger.info(f"Device {device['name']} with serial {device['serial']} already exists. Skipping...")
        return None

    # Create NetBox Device
    try:
        device_data = {
            'name': device["name"],
            'device_type': device_type_id,
            'tenant': ctx.tenant.id,
            'site': site.id,
        }
        
        if device.get("serial"):
            device_data['serial'] = device["serial"]

        logger.debug("Getting postable fields for NetBox API")
        available_fields = get_postable_fields(ctx.netbox_url, ctx.netbox_token, 'dcim/devices')
        logger.debug(f"Available NetBox API fields: {list(available_fields.keys())}")
        if 'role' in available_fields:
            logger.debug(f"Using 'role' field for device role (ID: {device_role_id})")
            device_data['role'] = device_role_id
        elif 'device_role' in available_fields:
            logger.debug(f"Using 'device_role' field for device role (ID: {device_role_id})")
            device_data['device_role'] = device_role_id
        else:
            logger.error(f'Could not determine the syntax for the role. Skipping device {device["name"]}.')
            return None

        # Add the device to Netbox
        logger.debug(f"Creating device in NetBox with data: {device_data}")
        nb_device = ctx.nb.dcim.devices.create(device_data)

        if nb_device:
            logger.info(f"Device {device['name']} serial {device.get('serial', 'N/A')} with ID {nb_device.id} successfully added to NetBox.")
            return nb_device
            
    except pynetbox.core.query.RequestError as e:
        error_message = str(e)
        if "Device name must be unique per site" in error_message:
            logger.warning(f"Device name {device['name']} already exists at site {site}. "
                           f"Trying with name {device['name']}_{device.get('serial', 'unknown')}.")
            try:
                device_data['name'] = f"{device['name']}_{device.get('serial', 'unknown')}"
                nb_device = ctx.nb.dcim.devices.create(device_data)
                if nb_device:
                    logger.info(f"Device {device['name']} with ID {nb_device.id} successfully added to NetBox.")
                    return nb_device
            except pynetbox.core.query.RequestError as e2:
                logger.exception(f"Failed to create device {device['name']} serial {device.get('serial')} at site {site}: {e2}")
                return None
        else:
            logger.exception(f"Failed to create device {device['name']} serial {device.get('serial')} at site {site}: {e}")
            return None
    
    return None


def process_base_device(
    unifi: Unifi, 
    site: Sites, 
    device: dict, 
    ctx: AppContext, 
    device_role, 
    vrf: pynetbox.core.response.Record
    ) -> pynetbox.core.response.Record | None:
    """
    Base device processing logic shared by wired and wireless devices.
    
    Args:
        unifi: UniFi API instance
        site: NetBox site object
        device: UniFi device dictionary
        ctx: Application context
        device_role: NetBox device role to assign
        
    Returns:
        NetBox device record or None if processing failed
    """
    logger.info(f"Processing device {device['name']} at site {site}...")
    logger.debug(f"Device details: Model={device.get('model')}, MAC={device.get('mac')}, IP={device.get('ip')}, Serial={device.get('serial')}")

    if not device.get("serial"):
        raise Exception(f"Missing serial number for device {device.get('name')}. Skipping...")

    # Get or create device type
    nb_device_type = get_or_create_device_type(device, ctx)
    if not nb_device_type:
        raise Exception(f"Failed to get or create device type for {device['name']}. Skipping...")

    # Create interface templates if port_table exists
    create_interface_templates(device, nb_device_type.id, ctx)

    # Create NetBox device
    nb_device = create_netbox_device(device, nb_device_type.id, device_role.id, site, ctx)
    if not nb_device:
        return None
    
    # Add primary IP address
    add_primary_ip_to_device(device, nb_device, site, vrf, ctx)

    # Add MAC address to vlan.1 interface if available
    interface = ctx.nb.dcim.interfaces.get(device_id=nb_device.id, name="vlan.1")
    if interface and device.get("mac"):
        add_mac_address_to_interface(device["mac"], interface, device['name'], ctx, set_as_primary=True)

    return nb_device

