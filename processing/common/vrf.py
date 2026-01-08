"""VRF operations."""
from logger import logger
from context import AppContext
from unifi.sites import Sites
import pynetbox


def get_or_create_vrf(site: Sites, ctx: AppContext) -> pynetbox.core.response.Record | None:
    """
    Get or create a VRF for a site.
    
    Args:
        site: NetBox site object
        ctx: Application context
        
    Returns:
        VRF record or None if creation failed
    """
    vrf_name = f"vrf_{site}"
    vrf = None
    logger.debug(f"Checking for existing VRF: {vrf_name}")
    try:
        vrf = ctx.nb.ipam.vrfs.get(name=vrf_name)
    except ValueError as e:
        error_message = str(e)
        if "get() returned more than one result." in error_message:
            logger.warning(f"Multiple VRFs with name {vrf_name} found. Using 1st one in the list.")
            vrfs = ctx.nb.ipam.vrfs.filter(name=vrf_name)
            for vrf_item in vrfs:
                vrf = vrf_item
                break
        else:
            logger.exception(f"Failed to get VRF {vrf_name} for site {site}: {e}. Skipping...")
            return None

    if not vrf:
        logger.debug(f"VRF {vrf_name} not found, creating new VRF")
        try:
            vrf = ctx.nb.ipam.vrfs.create({"name": vrf_name})
            if vrf:
                logger.info(f"VRF {vrf_name} with ID {vrf.id} successfully added to NetBox.")
        except Exception as e:
            logger.exception(f"Failed to create VRF {vrf_name} for site {site}: {e}")
            return None
    
    return vrf

