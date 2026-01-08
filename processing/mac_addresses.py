"""Process MAC addresses and add them to NetBox."""
from logger import logger
from unifi.sites import Sites
from unifi.unifi import Unifi
import pynetbox


def process_mac_addresses(unifi: Unifi, nb: pynetbox.api, site: Sites, device: dict, nb_ubiquity: dict, tenant):
    """Process MAC addresses and add them to NetBox."""
    # 1. 
    pass

