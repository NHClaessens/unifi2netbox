"""Process wired network devices (switches, routers)."""
from custom_types import Roles
from logger import logger
from processing.common import add_mac_address_to_interface
from unifi.sites import Sites
from unifi.unifi import Unifi
from context import AppContext
from processing.devices.base import process_base_device
import pynetbox


def process_wired_device(unifi: Unifi, site: Sites, device: dict, ctx: AppContext, vrf: pynetbox.core.response.Record):
    """
    Process a wired network device (switch, router) and add it to NetBox.
    
    Args:
        unifi: UniFi API instance
        site: NetBox site object
        device: UniFi device dictionary
        ctx: Application context
        vrf: VRF record
    """
    try:
        # Wired devices use the LAN role
        nb_device = process_base_device(unifi, site, device, ctx, ctx.roles[Roles.LAN], vrf)

        # Add MAC address to all ports in port_table
        for port in device.get("port_table", []):
            interface = ctx.nb.dcim.interfaces.get(device_id=nb_device.id, name=port["name"])
            mac = device.get("mac")
            if mac:
                add_mac_address_to_interface(mac, interface, device['name'], ctx, set_as_primary=True, allow_duplicate=True)
        
        if nb_device:
            logger.info(f"Successfully processed wired device {device['name']} at site {site}.")
            
    except Exception as e:
        logger.exception(f"Failed to process wired device {device.get('name')} at site {site}: {e}")

