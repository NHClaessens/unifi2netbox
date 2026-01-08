"""Process UniFi controllers and their sites."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from logger import logger
from unifi.unifi import Unifi
from util import match_sites_to_netbox
from context import AppContext
from processing.site import process_site

# Define threads for each layer
MAX_CONTROLLER_THREADS = 5  # Number of UniFi controllers to process concurrently
MAX_SITE_THREADS = 8  # Number of sites to process concurrently per controller


def process_controller(unifi_url: str, unifi_username: str, unifi_password: str, unifi_mfa_secret: str,
                       netbox_sites_dict: dict, ctx: AppContext):
    """
    Process all sites and devices for a specific UniFi controller.
    """
    logger.info(f"Processing controller {unifi_url}...")
    logger.debug(f"Initializing UniFi connection to: {unifi_url}")

    try:
        # Create a Unifi instance and authenticate
        unifi = Unifi(unifi_url, unifi_username, unifi_password, unifi_mfa_secret)
        logger.debug(f"UniFi connection established to: {unifi_url}")
        
        # Get all sites from the controller
        logger.debug(f"Fetching sites from controller: {unifi_url}")
        sites = unifi.sites
        logger.debug(f"Found {len(sites)} sites on controller: {unifi_url}")
        logger.info(f"Found {len(sites)} sites for controller {unifi_url}")

        with ThreadPoolExecutor(max_workers=MAX_SITE_THREADS) as executor:
            futures = []
            for site_name, site_obj in sites.items():
                logger.info(f"Processing site {site_name}...")
                nb_site = match_sites_to_netbox(site_name, netbox_sites_dict, ctx.config)

                if not nb_site:
                    logger.warning(f"No match found for Ubiquity site: {site_name}. Skipping...")
                    continue

                futures.append(executor.submit(process_site, unifi, site_name, nb_site, ctx))

            # Wait for all site-processing threads to complete
            for future in as_completed(futures):
                future.result()
    except Exception as e:
        logger.error(f"Error processing controller {unifi_url}: {e}")


def process_all_controllers(unifi_url_list: list[str], unifi_username: str, unifi_password: str, unifi_mfa_secret: str,
                            netbox_sites_dict: dict, ctx: AppContext):
    """
    Process all UniFi controllers in parallel.
    """
    with ThreadPoolExecutor(max_workers=MAX_CONTROLLER_THREADS) as executor:
        futures = []
        for url in unifi_url_list:
            futures.append(
                executor.submit(process_controller, url, unifi_username, unifi_password, unifi_mfa_secret,
                                netbox_sites_dict, ctx))

        # Wait for all controller-processing threads to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.exception(f"Error processing one of the UniFi controllers {url}: {e}")
                continue

