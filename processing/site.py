"""Process sites and their devices."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from logger import logger
from processing.common import get_or_create_vrf
from unifi.sites import Sites
from unifi.unifi import Unifi
from util import match_sites_to_netbox
from context import AppContext
from processing.device import process_device, process_client

# Define threads for each layer
MAX_DEVICE_THREADS = 8  # Number of devices to process concurrently per site
MAX_THREADS = 8  # Define threads based on available system cores or default


def fetch_site_devices(unifi, site_name):
    """Fetch devices for a specific site."""
    logger.info(f"Fetching devices for site {site_name}...")
    try:
        logger.debug(f"Getting site object for: {site_name}")
        site = unifi.site(site_name)
        if site:
            logger.debug(f"Retrieving devices for site: {site_name}")
            devices = site.device.all()
            logger.debug(f"Retrieved {len(devices)} devices for site: {site_name}")
            return devices
        else:
            logger.error(f"Site {site_name} not found")
            return None
    except Exception as e:
        logger.error(f"Failed to fetch devices for site {site_name}: {e}")
        return None


def process_site(unifi: Unifi, site_name: str, nb_site: Sites, ctx: AppContext):
    """
    Process devices for a given site and add them to NetBox.
    """
    logger.debug(f"Processing site {site_name}...")
    try:
        logger.debug(f"Fetching site object for: {site_name}")
        site = unifi.site(site_name)
        if site:
            logger.debug(f"Fetching devices for site: {site_name}")
            devices: list[dict] = site.device.all()
            logger.debug(f"Found {len(devices)} devices for site {site_name}")

            # Create VRF for site
            vrf = get_or_create_vrf(nb_site, ctx)
            if not vrf:
                logger.error(f"Failed to get or create VRF for site {site_name}. Skipping site.")
                return

            with ThreadPoolExecutor(max_workers=MAX_DEVICE_THREADS) as executor:
                futures = []
                for device in devices:
                    # TODO: VRF creation will happen multiple times as devices are processed in parallel
                    # Deleting all but one manually is a stopgap solution
                    futures.append(executor.submit(process_device, unifi, nb_site, device, ctx, vrf))

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Error processing a device at site {site_name}: {e}")

            client_devices: list[dict] = site.client_device.all()
            logger.debug(f"Found {len(client_devices)} client devices for site {site_name}")
            with ThreadPoolExecutor(max_workers=MAX_DEVICE_THREADS) as executor:
                futures = []
                for client_device in client_devices:
                    futures.append(executor.submit(process_client, unifi, nb_site, client_device, ctx))

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Error processing a client device at site {site_name}: {e}")
        else:
            logger.error(f"Site {site_name} not found")
    except Exception as e:
        logger.error(f"Failed to process site {site_name}: {e}")


def process_all_sites(unifi, netbox_sites_dict, ctx: AppContext):
    """Process all sites and their devices concurrently."""
    # Get all sites from the unifi module
    unifi_sites = unifi.sites
    if not unifi_sites:
        logger.error("Failed to fetch sites from UniFi controller.")
        return

    sites = {}
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # Fetch all devices per site concurrently
        future_to_site = {executor.submit(fetch_site_devices, unifi, site_name): site_name for site_name in unifi_sites.keys()}
        for future in as_completed(future_to_site):
            site_name = future_to_site[future]
            try:
                devices = future.result()
                if devices:
                    sites[site_name] = devices
                    logger.info(f"Successfully fetched devices for site {site_name}")
            except Exception as e:
                logger.error(f"Error fetching devices for site {site_name}: {e}")

    logger.info(f"Fetched {len(sites)} sites. Starting device processing...")

    # Process devices in parallel
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_device = {}
        for site_name, devices in sites.items():
            # Use the site mapping to find the corresponding NetBox site
            nb_site = match_sites_to_netbox(site_name, netbox_sites_dict, ctx.config)
            if not nb_site:
                logger.warning(f"No matching NetBox site found for Ubiquity site {site_name}. Add mapping in site_mapping.yaml. Skipping...")
                continue
            for device in devices:
                future = executor.submit(process_device, unifi, nb_site, device, ctx)
                future_to_device[future] = (site_name, device)

        for future in as_completed(future_to_device):
            site_name, device = future_to_device[future]
            try:
                future.result()
                logger.info(f"Successfully processed device {device['name']} at site {site_name}.")
            except Exception as e:
                logger.error(f"Error processing device {device['name']} at site {site_name}: {e}")

