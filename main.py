from dotenv import load_dotenv
import os
import requests
import warnings
import logging
import pynetbox 
from urllib3.exceptions import InsecureRequestWarning
from util import get_or_create_roles, load_config, prepare_netbox_sites, setup_logging
from processing import process_all_controllers
from logger import logger
from context import AppContext
# Suppress only the InsecureRequestWarning
warnings.simplefilter("ignore", InsecureRequestWarning)

load_dotenv()

def add_ip_to_device(ip: str, device_id: int, nb: pynetbox.api):
    """
    Add an IP address to a device in NetBox.
    """
    nb.ipam.ip_addresses.create({
        "address": ip,
        "device": device_id,
    })


# Structure:
# 1. Get all UniFi controllers
# 2. Process all controllers in parallel
#   3. For each controller, process all sites in parallel
#      4. For each site, process all devices in parallel
#      5. For each device, process all client devices in parallel
#      6. For each device, process all cables/connections in parallel (done afterwards so devices will exist in NetBox)

# TODO:
# - Add a way to delete devices from NetBox if they are not in UniFi
# - Perhaps add a list of devices to config, to then ssh into to get interfaces and IPs
# - When configuring cables, check if the target port is connected to a patch panel, and if so, use the patch panel's interface to create the cable

if __name__ == "__main__":
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='Sync UniFi devices to NetBox')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose (debug) logging')
    args = parser.parse_args()
    
    # Configure logging with appropriate level based on verbose flag
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)
    
    if args.verbose:
        logger.debug("Verbose logging enabled")
    logger.debug("Loading configuration")
    config: dict = load_config()
    logger.debug("Configuration loaded successfully")
    try:
        unifi_url_list: list[str] = config['UNIFI']['URLS']
    except ValueError:
        logger.exception("Unifi URL is missing from configuration.")
        raise SystemExit(1)

    try:
        unifi_username = os.getenv('UNIFI_USERNAME')
        unifi_password = os.getenv('UNIFI_PASSWORD')
        unifi_mfa_secret = os.getenv('UNIFI_MFA_SECRET')
    except KeyError:
        logger.exception("Unifi username or password is missing from environment variables.")
        raise SystemExit(1)

    # Connect to Netbox
    try:
        netbox_url: str = config['NETBOX']['URL']
    except ValueError:
        logger.exception("Netbox URL is missing from configuration.")
        raise SystemExit(1)
    try:
        netbox_token = os.getenv('NETBOX_TOKEN')
    except KeyError:
        logger.exception("Netbox token is missing from environment variables.")
        raise SystemExit(1)

    # Create a custom HTTP session as this script will often exceed the default pool size of 10
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50)

    # Adjust connection pool size
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    logger.debug(f"Initializing NetBox API connection to: {netbox_url}")
    nb = pynetbox.api(netbox_url, token=netbox_token, threading=True)
    nb.http_session.verify = False
    nb.http_session = session  # Attach the custom session
    logger.debug("NetBox API connection established")

    nb_ubiquity = nb.dcim.manufacturers.get(slug='ubiquity')
    try:
        tenant_name = config['NETBOX']['TENANT']
    except ValueError:
        logger.exception("Netbox tenant is missing from configuration.")
        raise SystemExit(1)

    tenant = nb.tenancy.tenants.get(name=tenant_name)

    logger.debug("Fetching all NetBox sites")
    netbox_sites = nb.dcim.sites.all()
    logger.debug(f"Found {len(netbox_sites)} sites in NetBox")

    # Preprocess NetBox sites
    logger.debug("Preparing NetBox sites dictionary")
    netbox_sites_dict = prepare_netbox_sites(netbox_sites)
    logger.debug(f"Prepared {len(netbox_sites_dict)} NetBox sites for mapping")

    if not nb_ubiquity:
        nb_ubiquity = nb.dcim.manufacturers.create({'name': 'Ubiquity Networks', 'slug': 'ubiquity'})
        if nb_ubiquity:
            logger.info(f"Ubiquity manufacturer with ID {nb_ubiquity.id} successfully added to Netbox.")

    # Create application context
    ctx = AppContext(
        nb=nb,
        nb_ubiquity=nb_ubiquity,
        tenant=tenant,
        roles=get_or_create_roles(nb, config),
        netbox_url=netbox_url,
        netbox_token=netbox_token,
        config=config
    )

    # Process all UniFi controllers in parallel
    process_all_controllers(
        unifi_url_list, 
        unifi_username, 
        unifi_password, 
        unifi_mfa_secret,
        netbox_sites_dict, 
        ctx,
    )
