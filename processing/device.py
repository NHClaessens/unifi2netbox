import ipaddress
import pynetbox
import slugify
from logger import logger
from unifi.sites import Sites
from unifi.unifi import Unifi
from util import get_postable_fields
from context import AppContext


def process_device(unifi: Unifi, site: Sites, device: dict, ctx: AppContext):
    """Process a device and add it to NetBox."""
    try:
        logger.info(f"Processing device {device['name']} at site {site}...")
        logger.debug(f"Device details: Model={device.get('model')}, MAC={device.get('mac')}, IP={device.get('ip')}, Serial={device.get('serial')}")

        # Determine device role
        if str(device.get("is_access_point", "false")).lower() == "true":
            nb_device_role = ctx.wireless_role
        else:
            nb_device_role = ctx.lan_role

        if not device.get("serial"):
            logger.warning(f"Missing serial number for device {device.get('name')}. Skipping...")
            return

        # VRF creation
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
                return

        if not vrf:
            logger.debug(f"VRF {vrf_name} not found, creating new VRF")
            vrf = ctx.nb.ipam.vrfs.create({"name": vrf_name})
            if vrf:
                logger.info(f"VRF {vrf_name} with ID {vrf.id} successfully added to NetBox.")

        # Device Type creation
        logger.debug(f"Checking for existing device type: {device['model']} (manufacturer ID: {ctx.nb_ubiquity.id})")
        nb_device_type = ctx.nb.dcim.device_types.get(model=device["model"], manufacturer_id=ctx.nb_ubiquity.id)
        if not nb_device_type:
            try:
                nb_device_type = ctx.nb.dcim.device_types.create({"manufacturer": ctx.nb_ubiquity.id, "model": device["model"],
                                                              "slug": slugify(f'{ctx.nb_ubiquity.name}-{device["model"]}')})
                if nb_device_type:
                    logger.info(f"Device type {device['model']} with ID {nb_device_type.id} successfully added to NetBox.")
            except pynetbox.core.query.RequestError as e:
                logger.error(f"Failed to create device type for {device['name']} at site {site}: {e}")
                return
            if len(device.get("port_table", [])) > 0:
                logger.warning(f"Port table for device {device['name']}: {len(device.get("port_table", []))}\n{device.get("port_table")}")
                for port in device["port_table"]:
                    # Choices can be found here: https://github.com/netbox-community/netbox/blob/main/netbox/dcim/choices.py
                    SPEED_MAP = {
                        "GE": "1000base-t",
                        "2P5GE": "2.5gbase-t",
                    }
                    port_type = SPEED_MAP.get(port["media"])
                    if port_type:
                        try:
                            template = ctx.nb.dcim.interface_templates.create({
                                "device_type": nb_device_type.id,
                                "name": port["name"],
                                "type": port_type,
                            })
                            if template:
                                logger.info(f"Interface template {port['name']} with ID {template.id} successfully added to NetBox.")
                        except pynetbox.core.query.RequestError as e:
                            logger.exception(f"Failed to create interface template for {device['name']} at site {site}: {e}")

        # Check for existing device
        logger.debug(f"Checking if device already exists: {device['name']} (serial: {device['serial']})")
        if ctx.nb.dcim.devices.get(site_id=site.id, serial=device["serial"]):
            logger.info(f"Device {device['name']} with serial {device['serial']} already exists. Skipping...")
            return



        # Create NetBox Device
        try:
            device_data = {
                    'name': device["name"],
                    'device_type': nb_device_type.id,
                    'tenant': ctx.tenant.id,
                    'site': site.id,
                    'serial': device["serial"]
                }

            logger.debug("Getting postable fields for NetBox API")
            available_fields = get_postable_fields(ctx.netbox_url, ctx.netbox_token, 'dcim/devices')
            logger.debug(f"Available NetBox API fields: {list(available_fields.keys())}")
            if 'role' in available_fields:
                logger.debug(f"Using 'role' field for device role (ID: {nb_device_role.id})")
                device_data['role'] = nb_device_role.id
            elif 'device_role' in available_fields:
                logger.debug(f"Using 'device_role' field for device role (ID: {nb_device_role.id})")
                device_data['device_role'] = nb_device_role.id
            else:
                logger.error(f'Could not determine the syntax for the role. Skipping device {device["name"]}, '
                                f'{device["serial"]}.')
                return None

            # Add the device to Netbox
            logger.debug(f"Creating device in NetBox with data: {device_data}")
            nb_device = ctx.nb.dcim.devices.create(device_data)

            if nb_device:
                logger.info(f"Device {device['name']} serial {device['serial']} with ID {nb_device.id} successfully added to NetBox.")
        except pynetbox.core.query.RequestError as e:
            error_message = str(e)
            if "Device name must be unique per site" in error_message:
                logger.warning(f"Device name {device['name']} already exists at site {site}. "
                               f"Trying with name {device['name']}_{device['serial']}.")
                try:
                    # Just update the name in the existing device_data dictionary
                    device_data['name'] = f"{device['name']}_{device['serial']}"
                    
                    # Add the device to Netbox with updated name
                    nb_device = ctx.nb.dcim.devices.create(device_data)
                    if nb_device:
                        logger.info(f"Device {device['name']} with ID {nb_device.id} successfully added to NetBox.")
                except pynetbox.core.query.RequestError as e2:
                    logger.exception(f"Failed to create device {device['name']} serial {device['serial']} at site {site}: {e2}")
                    return
            else:
                logger.exception(f"Failed to create device {device['name']} serial {device['serial']} at site {site}: {e}")
                return

        # Add primary IP if available
        try:
            ipaddress.ip_address(device["ip"])
        except ValueError:
            logger.warning(f"Invalid IP {device['ip']} for device {device['name']}. Skipping...")
            return
        # get the prefix that this IP address belongs to
        prefixes = ctx.nb.ipam.prefixes.filter(contains=device['ip'], vrf_id=vrf.id)
        if not prefixes:
            logger.warning(f"No prefix found for IP {device['ip']} for device {device['name']}. Skipping...")
            return
        for prefix in prefixes:
            # Extract the prefix length (mask) from the prefix
            subnet_mask = prefix.prefix.split('/')[1]
            ip = f'{device["ip"]}/{subnet_mask}'
            break
        if nb_device:
            interface = ctx.nb.dcim.interfaces.get(device_id=nb_device.id, name="vlan.1")
            if not interface:
                try:
                    interface = ctx.nb.dcim.interfaces.create(device=nb_device.id,
                                                          name="vlan.1",
                                                          type="virtual",
                                                          enabled=True,
                                                          vrf_id=vrf.id,)
                    if interface:
                        logger.info(
                            f"Interface vlan.1 for device {device['name']} with ID {interface.id} successfully added to NetBox.")
                except pynetbox.core.query.RequestError as e:
                    logger.exception(
                        f"Failed to create interface vlan.1 for device {device['name']} at site {site}: {e}")
                    return
            nb_ip = ctx.nb.ipam.ip_addresses.get(address=ip, vrf_id=vrf.id, tenant_id=ctx.tenant.id)
            if not nb_ip:
                try:
                    nb_ip = ctx.nb.ipam.ip_addresses.create({
                        "assigned_object_id": interface.id,
                        "assigned_object_type": 'dcim.interface',
                        "address": ip,
                        "vrf_id": vrf.id,
                        "tenant_id": ctx.tenant.id,
                        "status": "active",
                    })
                    if nb_ip:
                        logger.info(f"IP address {ip} with ID {nb_ip.id} successfully added to NetBox.")
                except pynetbox.core.query.RequestError as e:
                    logger.exception(f"Failed to create IP address {ip} for device {device['name']} at site {site}: {e}")
                    return
            if nb_ip:
                nb_device.primary_ip4 = nb_ip.id
                nb_device.save()
                logger.info(f"Device {device['name']} with IP {ip} added to NetBox.")




    except Exception as e:
        logger.exception(f"Failed to process device {device['name']} at site {site}: {e}")
