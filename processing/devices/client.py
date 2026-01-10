"""Process client devices (wireless clients, wired clients)."""
from logger import logger
from unifi.sites import Sites
from unifi.unifi import Unifi
from context import AppContext

def process_client_device(unifi: Unifi, site: Sites, client: dict, ctx: AppContext):
    """
    Process a client device and add it to NetBox.
    
    Client devices can be either wired or wireless. This function handles
    both types and creates appropriate records in NetBox.
    
    Args:
        unifi: UniFi API instance
        site: NetBox site object
        client: UniFi client device dictionary
        ctx: Application context
    """
    try:
        logger.info(f"Processing client device {client.get('name', client.get('mac', 'Unknown'))} at site {site}...")
        
        # Check if client is wired or wireless
        is_wired = client.get("is_wired", False)
        
        if is_wired:
            # TODO: Process wired client devices
            # This might involve:
            # - Creating a device or virtual machine in NetBox
            # - Linking to the switch port via MAC address
            logger.debug(f"Client {client.get('name')} {client.get('mac')} is a wired client\n  - IP: {client.get('ip')}")
        else:
            # TODO: Process wireless client devices
            # This might involve:
            # - Creating a device or virtual machine in NetBox
            # - Linking to the access point and wireless network
            # - Recording connection details (SSID, frequency, WiFi standard)
            logger.debug(f"Client {client.get('name')} {client.get('mac')} is a wireless client\n  - SSID: {client.get('essid')}\n  - Radio: {client.get('radio')} ({'2.4 GHz' if client.get('radio') == 'ng' else '5 GHz'})\n  - IP: {client.get('ip')}\n  - AP MAC: {client.get('ap_mac')}")
        
        # TODO: Implement client device creation in NetBox
        # This is a placeholder for future implementation
        
    except Exception as e:
        logger.exception(f"Failed to process client device {client.get('name', client.get('mac', 'Unknown'))} at site {site}: {e}")

