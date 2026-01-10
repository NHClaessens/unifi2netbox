"""Main device processing router."""
from logger import logger
from unifi.sites import Sites
from unifi.unifi import Unifi
from context import AppContext
from processing.devices import process_wired_device, process_wireless_device, process_client_device
import pynetbox


def process_device(unifi: Unifi, site: Sites, device: dict, ctx: AppContext, vrf: pynetbox.core.response.Record):
    """
    Route device processing to the appropriate handler based on device type.
    
    Args:
        unifi: UniFi API instance
        site: NetBox site object
        device: UniFi device dictionary
        ctx: Application context
    """
    try:
        # Determine device type and route to appropriate processor
        is_access_point = str(device.get("is_access_point", "false")).lower() == "true"
        
        if is_access_point:
            # Process as wireless device (access point)
            process_wireless_device(unifi, site, device, ctx, vrf)
        else:
            # Process as wired device (switch, router, etc.)
            process_wired_device(unifi, site, device, ctx, vrf)
            
    except Exception as e:
        logger.exception(f"Failed to route device {device.get('name')} at site {site}: {e}")


def process_client(unifi: Unifi, site: Sites, client: dict, ctx: AppContext):
    """
    Process a client device.
    
    Args:
        unifi: UniFi API instance
        site: NetBox site object
        client: UniFi client device dictionary
        ctx: Application context
    """
    process_client_device(unifi, site, client, ctx)
