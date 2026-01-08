"""Device type operations."""
from logger import logger
from context import AppContext
import pynetbox
import slugify


def get_or_create_device_type(device: dict, ctx: AppContext) -> pynetbox.core.response.Record | None:
    """
    Get or create a device type in NetBox.
    
    Args:
        device: UniFi device dictionary
        ctx: Application context
        
    Returns:
        Device type record or None if creation failed
    """
    logger.debug(f"Checking for existing device type: {device['model']} (manufacturer ID: {ctx.nb_ubiquity.id})")
    nb_device_type = ctx.nb.dcim.device_types.get(model=device["model"], manufacturer_id=ctx.nb_ubiquity.id)
    if not nb_device_type:
        try:
            nb_device_type = ctx.nb.dcim.device_types.create({
                "manufacturer": ctx.nb_ubiquity.id,
                "model": device["model"],
                "slug": slugify(f'{ctx.nb_ubiquity.name}-{device["model"]}')
            })
            if nb_device_type:
                logger.info(f"Device type {device['model']} with ID {nb_device_type.id} successfully added to NetBox.")
        except pynetbox.core.query.RequestError as e:
            logger.error(f"Failed to create device type for {device['name']}: {e}")
            return None
    
    return nb_device_type


def create_interface_templates(device: dict, device_type_id: int, ctx: AppContext) -> None:
    """
    Create interface templates for a device type based on port_table.
    
    Args:
        device: UniFi device dictionary
        device_type_id: NetBox device type ID
        ctx: Application context
    """
    template_exists = ctx.nb.dcim.interface_templates.filter(device_type=device_type_id)
    if template_exists:
        logger.debug(f"Interface templates for device {device['name']} already exist. Skipping...")
        return
    
    port_table = device.get("port_table", [])
    if len(port_table) > 0:
        logger.debug(f"Port table for device {device['name']}: {len(port_table)} ports")
        for port in port_table:
            # Choices can be found here: https://github.com/netbox-community/netbox/blob/main/netbox/dcim/choices.py
            SPEED_MAP = {
                "GE": "1000base-t",
                "2P5GE": "2.5gbase-t",
            }
            port_type = SPEED_MAP.get(port.get("media"))
            if port_type:
                try:
                    template = ctx.nb.dcim.interface_templates.create({
                        "device_type": device_type_id,
                        "name": port["name"],
                        "type": port_type,
                    })
                    if template:
                        logger.info(f"Interface template {port['name']} with ID {template.id} successfully added to NetBox.")
                except pynetbox.core.query.RequestError as e:
                    logger.exception(f"Failed to create interface template {port['name']} for device {device['name']}: {e}")

