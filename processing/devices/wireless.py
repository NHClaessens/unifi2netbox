"""Process wireless network devices (access points)."""
from logger import logger
from unifi.sites import Sites
from unifi.unifi import Unifi
from context import AppContext
from processing.devices.base import process_base_device


def process_wireless_device(unifi: Unifi, site: Sites, device: dict, ctx: AppContext):
    """
    Process a wireless network device (access point) and add it to NetBox.
    
    This function handles access points and can be extended to process
    wireless networks (VAPs) and their configurations.
    
    Args:
        unifi: UniFi API instance
        site: NetBox site object
        device: UniFi device dictionary
        ctx: Application context
    """
    try:
        # Wireless devices use the wireless role
        nb_device = process_base_device(unifi, site, device, ctx, ctx.wireless_role)
        
        if nb_device:
            logger.info(f"Successfully processed wireless device {device['name']} at site {site}.")
            
            # TODO: Process wireless networks (VAPs) from vap_table
            # This can include:
            # - Creating wireless LANs in NetBox
            # - Mapping frequency (2.4 GHz vs 5 GHz)
            # - Mapping WiFi standard (802.11n, 802.11ac, 802.11ax, etc.)
            # - Channel and bandwidth information
            vap_table = device.get("vap_table", [])
            if vap_table:
                logger.debug(f"Device {device['name']} has {len(vap_table)} wireless networks (VAPs)")
                # Future: Process VAPs here
        else:
            logger.warning(f"Failed to process wireless device {device['name']} at site {site}.")
            
    except Exception as e:
        logger.exception(f"Failed to process wireless device {device.get('name')} at site {site}: {e}")

