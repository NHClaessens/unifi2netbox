"""Process wired network devices (switches, routers)."""
from logger import logger
from unifi.sites import Sites
from unifi.unifi import Unifi
from context import AppContext
from processing.devices.base import process_base_device


def process_wired_device(unifi: Unifi, site: Sites, device: dict, ctx: AppContext):
    """
    Process a wired network device (switch, router) and add it to NetBox.
    
    Args:
        unifi: UniFi API instance
        site: NetBox site object
        device: UniFi device dictionary
        ctx: Application context
    """
    try:
        # Wired devices use the LAN role
        nb_device = process_base_device(unifi, site, device, ctx, ctx.lan_role)
        
        if nb_device:
            logger.info(f"Successfully processed wired device {device['name']} at site {site}.")
        else:
            logger.warning(f"Failed to process wired device {device['name']} at site {site}.")
            
    except Exception as e:
        logger.exception(f"Failed to process wired device {device.get('name')} at site {site}: {e}")

