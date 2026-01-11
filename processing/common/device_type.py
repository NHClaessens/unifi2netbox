"""Device type operations."""
from custom_types import MAX_SPEED_MAP, SPEED_MAP
from logger import logger
from context import AppContext
import pynetbox
from slugify import slugify


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
            # TODO: not my favorite solution, but it works for now
            if e.req.status_code == 500 and "IntegrityError" in e.message:
                return ctx.nb.dcim.device_types.get(model=device["model"], manufacturer_id=ctx.nb_ubiquity.id)
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
    port_table = device.get("port_table", [])
    ethernet_table = device.get("ethernet_table", [])
    exising_templates = ctx.nb.dcim.interface_templates.filter(device_type=device_type_id)
    logger.warning(f"Ethernet table for device {device['name']}: {ethernet_table}, port table len: {len(port_table)}, template exists: {len(exising_templates)}")
    if exising_templates:
        logger.debug(f"Interface templates for device {device['name']} already exist. Deleting...")
        delete_success = exising_templates.delete()
        if not delete_success:
            logger.error(f"Failed to delete interface templates for device {device['name']}.")
            return
    
 
    if len(port_table) > 0:
        logger.debug(f"Port table for device {device['name']}: {len(port_table)} ports")
        for port in port_table:
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
    elif len(ethernet_table) > 0:
        # Use this for APs with single ports, as they do not define a port_table
        logger.debug(f"Ethernet table for device {device['name']}: {len(ethernet_table)} ports")
        template = ctx.nb.dcim.interface_templates.get(device_type=device_type_id, name='eth0')
        if not template:
            template = ctx.nb.dcim.interface_templates.create({
                "device_type": device_type_id,
                "name": 'eth0',
                "type": MAX_SPEED_MAP.get(device['uplink'].get("max_speed"), "1000base-t"),
            })
            if template:
                logger.info(f"Interface template eth0 with ID {template.id} successfully added to NetBox.")
