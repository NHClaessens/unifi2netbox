"""IP address operations."""
import ipaddress
from logger import logger
from context import AppContext
from unifi.sites import Sites
import pynetbox


def add_primary_ip_to_device(device: dict, nb_device: pynetbox.core.response.Record, 
                            site: Sites, vrf: pynetbox.core.response.Record, ctx: AppContext) -> bool:
    """
    Add primary IP address to a device in NetBox.
    
    Args:
        device: UniFi device dictionary
        nb_device: NetBox device record
        site: NetBox site object
        vrf: VRF record
        ctx: Application context
        
    Returns:
        True if successful, False otherwise
    """
    device_ip = device.get("ip")
    if not device_ip:
        logger.debug(f"No IP address for device {device['name']}. Skipping IP assignment.")
        return False
    
    # Validate IP address
    try:
        ipaddress.ip_address(device_ip)
    except ValueError:
        logger.warning(f"Invalid IP {device_ip} for device {device['name']}. Skipping...")
        return False
    
    # Get the prefix that this IP address belongs to
    prefixes = ctx.nb.ipam.prefixes.filter(contains=device_ip, vrf_id=vrf.id)
    if not prefixes:
        logger.warning(f"No prefix found for IP {device_ip} for device {device['name']}. Skipping...")
        return False
    
    # Extract the prefix length (mask) from the prefix
    prefix = next(iter(prefixes), None)
    if not prefix:
        return False
    
    subnet_mask = prefix.prefix.split('/')[1]
    ip = f'{device_ip}/{subnet_mask}'
    
    # Get or create vlan.1 interface
    interface = ctx.nb.dcim.interfaces.get(device_id=nb_device.id, name="vlan.1")
    if not interface:
        try:
            interface = ctx.nb.dcim.interfaces.create(
                device=nb_device.id,
                name="vlan.1",
                type="virtual",
                enabled=True,
                vrf_id=vrf.id,
            )
            if interface:
                logger.info(
                    f"Interface vlan.1 for device {device['name']} with ID {interface.id} successfully added to NetBox.")
        except pynetbox.core.query.RequestError as e:
            logger.exception(
                f"Failed to create interface vlan.1 for device {device['name']} at site {site}: {e}")
            return False
    
    # Get or create IP address
    nb_ip = ctx.nb.ipam.ip_addresses.get(address=ip, vrf_id=vrf.id, tenant_id=ctx.tenant.id)
    if not nb_ip:
        try:
            nb_ip = ctx.nb.ipam.ip_addresses.create({
                "assigned_object_id": interface.id,
                "assigned_object_type": 'dcim.interface',
                "address": ip,
                "vrf_id": vrf.id,
                "tenant_id": ctx.tenant.id,
                "status": "active",
            })
            if nb_ip:
                logger.info(f"IP address {ip} with ID {nb_ip.id} successfully added to NetBox.")
        except pynetbox.core.query.RequestError as e:
            logger.exception(f"Failed to create IP address {ip} for device {device['name']} at site {site}: {e}")
            return False
    
    # Set as primary IP
    if nb_ip:
        try:
            nb_device.primary_ip4 = nb_ip.id
            nb_device.save()
            logger.info(f"Device {device['name']} with IP {ip} added to NetBox.")
            return True
        except Exception as e:
            logger.exception(f"Failed to set primary IP for device {device['name']}: {e}")
            return False
    
    return False


def add_ip_address_to_interface(ip: str, interface_id: int, vrf: pynetbox.core.response.Record, device_name: str, ctx: AppContext) -> bool:
    """
    Add IP address to an interface in NetBox.
    
    Args:
        ip: IP address string
        interface_id: NetBox interface ID
        device_name: Device name for logging
        ctx: Application context
    """
    if not ip:
        logger.debug(f"No IP address for device {device_name}. Skipping IP assignment.")
        return False
    
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        logger.warning(f"Invalid IP {ip} for device {device_name}. Skipping...")
        return False
    
    # Get or create IP address
    nb_ip = ctx.nb.ipam.ip_addresses.get(address=ip, vrf_id=vrf.id, tenant_id=ctx.tenant.id)
    if not nb_ip:
        try:
            nb_ip = ctx.nb.ipam.ip_addresses.create({
                "assigned_object_id": interface_id,
                "assigned_object_type": 'dcim.interface',
                "address": ip,
                "vrf_id": vrf.id,
                "tenant_id": ctx.tenant.id,
                "status": "active",
            })
            if nb_ip:
                logger.info(f"IP address {ip} with ID {nb_ip.id} successfully added to NetBox.")
                return True
        except pynetbox.core.query.RequestError as e:
            logger.exception(f"Failed to create IP address {ip} for device {device_name}: {e}")
            return False
    
    return False