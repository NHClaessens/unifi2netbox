"""Process wireless network devices (access points)."""
import pynetbox
from custom_types import RADIO_TYPE_MAP, Roles
from logger import logger
from unifi.sites import Sites
from unifi.unifi import Unifi
from context import AppContext
from processing.devices.base import process_base_device
from processing.common.mac_address import add_mac_address_to_interface


def format_rf_channel(radio: str, channel: int) -> str:
    """
    Format channel information into NetBox rf_channel format.
    
    Format: "{band}-{channel}-{frequency}-{width}"
    Example: "2.4g-1-2412-22"
    
    The bandwidth is determined by NetBox's channel definitions, not the VAP bandwidth.
    
    Args:
        radio: Radio type ("ng" for 2.4 GHz, "na" for 5 GHz, "ax" for 6 GHz)
        channel: Channel number
        
    Returns:
        Formatted rf_channel string, or None if channel is not valid
    """
    # Map radio type to band string
    band_map = {
        "ng": "2.4g",
        "na": "5g",
        "ax": "6g",
    }
    band = band_map.get(radio, "2.4g")
    
    # Calculate frequency and get bandwidth based on band and channel
    if radio == "ng":  # 2.4 GHz
        # 2.4 GHz: frequency = 2407 + (channel * 5) MHz, always 22 MHz bandwidth
        if not (1 <= channel <= 13):
            return None
        frequency = 2407 + (channel * 5)
        bandwidth = 22
    elif radio == "na":  # 5 GHz
        # 5 GHz: frequency = 5000 + (channel * 5) MHz
        # Bandwidth is determined by channel according to NetBox definitions
        frequency = 5000 + (channel * 5)
        bandwidth = _get_5ghz_bandwidth(channel)
        if bandwidth is None:
            return None
    elif radio == "ax":  # 6 GHz
        # 6 GHz: frequency = 5950 + (channel * 5) MHz
        # Bandwidth is determined by channel according to NetBox definitions
        frequency = 5950 + (channel * 5)
        bandwidth = _get_6ghz_bandwidth(channel)
        if bandwidth is None:
            return None
    else:
        # Default to 2.4 GHz calculation
        if not (1 <= channel <= 13):
            return None
        frequency = 2407 + (channel * 5)
        bandwidth = 22
    
    return f"{band}-{channel}-{frequency}-{bandwidth}"


def _get_5ghz_bandwidth(channel: int) -> int | None:
    """
    Get the bandwidth for a 5 GHz channel according to NetBox definitions.
    
    Args:
        channel: Channel number
        
    Returns:
        Bandwidth in MHz, or None if channel is not valid
    """
    # 5 GHz channel to bandwidth mapping based on NetBox definitions
    bandwidth_map = {
        # Lower 5 GHz band
        32: 20, 34: 40, 36: 20, 38: 40, 40: 20, 42: 80, 44: 20, 46: 40,
        48: 20, 50: 160, 52: 20, 54: 40, 56: 20, 58: 80, 60: 20, 62: 40, 64: 20,
        # Middle 5 GHz band
        100: 20, 102: 40, 104: 20, 106: 80, 108: 20, 110: 40, 112: 20, 114: 160,
        116: 20, 118: 40, 120: 20, 122: 80, 124: 20, 126: 40, 128: 20,
        # Upper 5 GHz band
        132: 20, 134: 40, 136: 20, 138: 80, 140: 20, 142: 40, 144: 20,
        149: 20, 151: 40, 153: 20, 155: 80, 157: 20, 159: 40, 161: 20, 163: 160,
        165: 20, 167: 40, 169: 20, 171: 80, 173: 20, 175: 40, 177: 20,
    }
    return bandwidth_map.get(channel)


def _get_6ghz_bandwidth(channel: int) -> int | None:
    """
    Get the bandwidth for a 6 GHz channel according to NetBox definitions.
    
    Args:
        channel: Channel number
        
    Returns:
        Bandwidth in MHz, or None if channel is not valid
    """
    # 6 GHz channel to bandwidth mapping based on NetBox definitions
    bandwidth_map = {
        1: 20, 3: 40, 5: 20, 7: 80, 9: 20, 11: 40, 13: 20, 15: 160,
        17: 20, 19: 40, 21: 20, 23: 80, 25: 20, 27: 40, 29: 20, 31: 320,
        33: 20, 35: 40, 37: 20, 39: 80, 41: 20, 43: 40, 45: 20, 47: 160,
        49: 20, 51: 40, 53: 20, 55: 80, 57: 20, 59: 40, 61: 20,
        65: 20, 67: 40, 69: 20, 71: 80, 73: 20, 75: 40, 77: 20, 79: 160,
        81: 20, 83: 40, 85: 20, 87: 80, 89: 20, 91: 40, 93: 20, 95: 320,
        97: 20, 99: 40, 101: 20, 103: 80, 105: 20, 107: 40, 109: 20, 111: 160,
        113: 20, 115: 40, 117: 20, 119: 80, 121: 20, 123: 40, 125: 20,
        129: 20, 131: 40, 133: 20, 135: 80, 137: 20, 139: 40, 141: 20, 143: 160,
        145: 20, 147: 40, 149: 20, 151: 80, 153: 20, 155: 40, 157: 20, 159: 320,
        161: 20, 163: 40, 165: 20, 167: 80, 169: 20, 171: 40, 173: 20, 175: 160,
        177: 20, 179: 40, 181: 20, 183: 80, 185: 20, 187: 40, 189: 20,
        193: 20, 195: 40, 197: 20, 199: 80, 201: 20, 203: 40, 205: 20, 207: 160,
        209: 20, 211: 40, 213: 20, 215: 80, 217: 20, 219: 40, 221: 20,
        225: 20, 227: 40, 229: 20, 233: 20,
    }
    return bandwidth_map.get(channel)


def process_wireless_device(unifi: Unifi, site: Sites, device: dict, ctx: AppContext, vrf: pynetbox.core.response.Record):
    """
    Process a wireless network device (access point) and add it to NetBox.
    
    This function handles access points and can be extended to process
    wireless networks (VAPs) and their configurations.
    
    Args:
        unifi: UniFi API instance
        site: NetBox site object
        device: UniFi device dictionary
        ctx: Application context
        vrf: VRF record
    """
    try:
        # Wireless devices use the wireless role
        nb_device = process_base_device(unifi, site, device, ctx, ctx.roles[Roles.WIRELESS], vrf)
        
        if nb_device:
            logger.info(f"Successfully processed wireless device {device['name']} at site {site}.")
            
            # Process wireless networks (VAPs) from vap_table
            vap_table = device.get("vap_table", [])
            if vap_table:
                logger.debug(f"Device {device['name']} has {len(vap_table)} wireless networks (VAPs)")
                for vap in vap_table:
                    process_wireless_vap(nb_device, site, vap, ctx, vrf)

            port_table = device.get("port_table", [])
            ethernet_table = device.get("ethernet_table", [])

            # For APs with more than 1 port
            if port_table:
                for port in port_table:
                    interface = ctx.nb.dcim.interfaces.get(device_id=nb_device.id, name=port["name"])
                    if interface:
                        add_mac_address_to_interface(device["mac"], interface, nb_device.name, ctx, set_as_primary=True, allow_duplicate=True)
            # For APs with single port
            elif ethernet_table:
                interface = ctx.nb.dcim.interfaces.get(device_id=nb_device.id, name="eth0")
                if interface:
                    add_mac_address_to_interface(device["mac"], interface, nb_device.name, ctx, set_as_primary=True, allow_duplicate=True)
    except Exception as e:
        logger.exception(f"Failed to process wireless device {device.get('name')} at site {site}: {e}")

def process_wireless_vap(nb_device: pynetbox.core.response.Record, site: Sites, vap: dict, ctx: AppContext, vrf: pynetbox.core.response.Record):
    """
    Process a wireless network (VAP) and add it to NetBox.
    
    Args:
        nb_device: NetBox device record
        site: NetBox site object
        vap: UniFi wireless network dictionary
        ctx: Application context
        vrf: VRF record
    """
    try:
        essid = vap.get('essid')
        vap_name = vap.get('name')
        
        if not essid:
            logger.warning(f"VAP {vap_name} has no ESSID. Skipping...")
            return
        
        if not vap_name:
            logger.warning(f"VAP with ESSID {essid} has no name. Skipping...")
            return
        
        logger.info(f"Processing wireless network {essid} (VAP: {vap_name}) at site {site}...")
        
        # 1. Check if wireless LAN exists, if not create it
        # TODO: this should not be done here, as it will create duplicates
        wireless_lan = get_or_create_wireless_lan(essid, site, vrf, ctx)
        
        interface = create_wireless_interface(nb_device, site, vap, ctx, vrf, wireless_lan)
        
        # Add MAC address (BSSID) to interface
        mac = vap.get('bssid')
        if mac and interface:
            add_mac_address_to_interface(mac, interface, nb_device.name, ctx, set_as_primary=True)
        
    except Exception as e:
        logger.exception(f"Failed to process wireless network {vap.get('name', 'Unknown')} at site {site}: {e}")

def get_or_create_wireless_lan(essid, site: Sites, vrf: pynetbox.core.response.Record, ctx: AppContext):
    """
    Get or create a wireless LAN in NetBox.
    
    Args:
        essid: ESSID of the wireless LAN
        site: NetBox site object
        vrf: VRF record
        ctx: Application context
    """
    wireless_lan = ctx.nb.wireless.wireless_lans.get(ssid=essid)
    if not wireless_lan:
        try:
            wireless_lan = ctx.nb.wireless.wireless_lans.create({
                'ssid': essid,
                'tenant': ctx.tenant.id,
                'status': 'active',
            })
            logger.info(f"Created wireless LAN {essid} with ID {wireless_lan.id} at site {site}.")
        except pynetbox.core.query.RequestError as e:
            logger.exception(f"Failed to create wireless LAN {essid} at site {site}: {e}")
            return
    else:
        logger.debug(f"Wireless LAN {essid} already exists with ID {wireless_lan.id}.")
    
    return wireless_lan

def create_wireless_interface(nb_device: pynetbox.core.response.Record, site: Sites, vap: dict, ctx: AppContext, vrf: pynetbox.core.response.Record, wireless_lan: pynetbox.core.response.Record):
    """
    Create a wireless interface in NetBox.
    
    Args:
        nb_device: NetBox device record
        site: NetBox site object
        vap: UniFi wireless network dictionary
        ctx: Application context
        vrf: VRF record
        wireless_lan: Wireless LAN record
    """
    # 2. Check if interface exists, if not create it
    radio = vap.get('radio', '')
    interface_type = RADIO_TYPE_MAP.get(radio, "ieee802.11n")  # Default to 802.11n if unknown
    vap_name = vap.get('name')
    interface = ctx.nb.dcim.interfaces.get(device_id=nb_device.id, name=vap_name)
    
    # Format rf_channel if channel is available
    # Note: Bandwidth is determined by NetBox's channel definitions, not the VAP bw field
    channel = vap.get('channel')
    rf_channel = None
    if channel and radio:
        try:
            rf_channel = format_rf_channel(radio, channel)
            if not rf_channel:
                logger.warning(f"Invalid channel {channel} for radio {radio} in VAP {vap_name}. Skipping rf_channel.")
        except Exception as e:
            logger.warning(f"Failed to format rf_channel for VAP {vap_name}: {e}")
    
    if not interface:
        try:
            interface_data = {
                'device': nb_device.id,
                'name': vap_name,
                'type': interface_type,
                'enabled': vap.get('up', True),
                'vrf': vrf.id,
                'rf_role': 'ap',  # Access point role
                'wireless_lans': [wireless_lan.id],
            }
            
            # Add rf_channel if available
            if rf_channel:
                interface_data['rf_channel'] = rf_channel
            interface = ctx.nb.dcim.interfaces.create(interface_data)
            logger.info(f"Created wireless interface {vap_name} with ID {interface.id} on device {nb_device.name}.")
        except pynetbox.core.query.RequestError as e:
            logger.exception(f"Failed to create interface {vap_name} for device {nb_device.name} at site {site}: {e}")
            return
    else:
        logger.debug(f"Interface {vap_name} already exists with ID {interface.id} on device {nb_device.name}.")
        # Update interface if needed (wireless_lan, channel, etc.)
        try:
            update_needed = False
            # Get current wireless_lan ID (handle both object and ID cases)
            current_wlan_id = interface.wireless_lan.id if hasattr(interface.wireless_lan, 'id') else interface.wireless_lan
            if current_wlan_id != wireless_lan.id:
                interface.wireless_lan = wireless_lan.id
                update_needed = True
            if rf_channel:
                current_rf_channel = interface.rf_channel
                if current_rf_channel != rf_channel:
                    interface.rf_channel = rf_channel
                    update_needed = True
            if update_needed:
                interface.save()
                logger.info(f"Updated interface {vap_name} on device {nb_device.name}.")
        except Exception as e:
            logger.warning(f"Failed to update interface {vap_name}: {e}")
    
    return interface