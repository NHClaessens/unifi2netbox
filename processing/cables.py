"""Process cables and add them to NetBox."""
from logger import logger
from unifi.sites import Sites
from unifi.unifi import Unifi
from util import get_unifi_site_name
from context import AppContext
import pynetbox


def process_cables(unifi: Unifi, nb: pynetbox.api, site: Sites, device: dict, nb_ubiquity: dict, tenant, ctx: AppContext):
    """Process cables and add them to NetBox."""

    # 1. Check if device alread exists in Netbox, based on MAC
    # 2. If device does not exist, fetch data from UniFi and create device in Netbox
    #   a. Create an interface object for the device
    #   b. Create an IP address object for the device
    #   c. Create a MAC address object for the device
    #   d. Assign it the "Wired"role
    # 3. If device exists, see if a cable already exists to this MAC address
    #   a. If cable exists, check if the cable is correct, if not, update the cable
    #   b. If it does not, create a cable object

    try:
        logger.info(f"Processing cables for device {device['name']} at site {site}...")
        logger.debug(f"Cables details: {device.get('port_table')}")
        logger.warning(f"Fetching devices from UniFi site: {site.name}")

        unifi_site_name = get_unifi_site_name(site.name, ctx.config)
        unifi_site = unifi.site(unifi_site_name)

        client_devices: list[dict] = unifi_site.client_device.all()
        unifi_site.device
        logger.warning(f"Find devices in {len(client_devices)}")
        import json
        with open("client_devices.json", "w") as f:
            json.dump(client_devices, f, indent=4)

        for port in device.get("port_table", []):
            logger.warning(f"last_connection: {port.get('last_connection')}")
            device_b = nb.dcim.devices.get(site_id=site.id, mac_address=port.get("last_connection").get("mac"))

            if not device_b:
                pass

            # nb.dcim.cables.create({
            #     "a_terminations": {
            #         "object_type": "dcim.interface",
            #         "object_id": port.get("a_terminations").get("object_id"),
            #     },
            #     "b_terminations": port.get("b_terminations"),
            #     "status": port.get("status"),
            # })
            
    except Exception as e:
        logger.exception(f"Failed to process cables for device {device['name']} at site {site}: {e}")

