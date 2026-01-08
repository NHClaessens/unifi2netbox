import logging
from main import logger
import yaml
import os

def load_site_mapping(config=None):
    """
    Load site mapping from configuration or YAML file.
    Returns a dictionary mapping UniFi site names to NetBox site names.
    
    :param config: Configuration dictionary loaded from config.yaml
    :return: Dictionary mapping UniFi site names to NetBox site names
    """
    # Initialize with empty mapping
    site_mapping = {}
    
    # First check if config has site mappings defined directly
    if config and 'UNIFI' in config and 'SITE_MAPPINGS' in config['UNIFI']:
        logger.debug("Loading site mappings from config.yaml")
        config_mappings = config['UNIFI']['SITE_MAPPINGS']
        if config_mappings:
            site_mapping.update(config_mappings)
            logger.debug(f"Loaded {len(config_mappings)} site mappings from config.yaml")
    
    # Check if we should use the external mapping file
    use_file_mapping = False
    if config and 'UNIFI' in config and 'USE_SITE_MAPPING' in config['UNIFI']:
        use_file_mapping = config['UNIFI']['USE_SITE_MAPPING']
        
    if use_file_mapping:
        site_mapping_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'site_mapping.yaml')
        logger.debug(f"Loading site mapping from file: {site_mapping_path}")
        
        # Check if file exists, if not create a default one
        if not os.path.exists(site_mapping_path):
            logger.warning(f"Site mapping file not found at {site_mapping_path}. Creating a default one.")
            os.makedirs(os.path.dirname(site_mapping_path), exist_ok=True)
            with open(site_mapping_path, 'w') as f:
                f.write("# Site mapping configuration\n")
                f.write("# Format: unifi_site_name: netbox_site_name\n")
                f.write("\"Default\": \"Default\"\n")
            
        try:
            with open(site_mapping_path, 'r') as f:
                file_mapping = yaml.safe_load(f) or {}
                logger.debug(f"Loaded {len(file_mapping)} mappings from site_mapping.yaml")
                # Update the mapping with file values (config values take precedence)
                for key, value in file_mapping.items():
                    if key not in site_mapping:  # Don't overwrite config mappings
                        site_mapping[key] = value
        except Exception as e:
            logger.error(f"Error loading site mapping file: {e}")
    
    logger.debug(f"Final site mapping has {len(site_mapping)} entries")
    return site_mapping

def get_netbox_site_name(unifi_site_name, config=None):
    """
    Get NetBox site name from UniFi site name using the mapping table.
    If no mapping exists, return the original name.
    
    :param unifi_site_name: The UniFi site name to look up
    :param config: Configuration dictionary loaded from config.yaml
    :return: The corresponding NetBox site name or the original name if no mapping exists
    """
    site_mapping = load_site_mapping(config)
    mapped_name = site_mapping.get(unifi_site_name, unifi_site_name)
    if mapped_name != unifi_site_name:
        logger.debug(f"Mapped UniFi site '{unifi_site_name}' to NetBox site '{mapped_name}'")
    return mapped_name

def get_unifi_site_name(netbox_site_name, config=None):
    """
    Get UniFi site name from NetBox site name using the mapping table.
    If no mapping exists, return the original name.
    """
    site_mapping = load_site_mapping(config)
    unifi_site_tuple = next(filter(lambda x: x[1] == netbox_site_name, site_mapping.items()), None)
    if not unifi_site_tuple:
        return None
    return unifi_site_tuple[0]

def prepare_netbox_sites(netbox_sites):
    """
    Pre-process NetBox sites for lookup.

    :param netbox_sites: List of NetBox site objects.
    :return: A dictionary mapping NetBox site names to the original NetBox site objects.
    """
    netbox_sites_dict = {}
    for netbox_site in netbox_sites:
        netbox_sites_dict[netbox_site.name] = netbox_site
    return netbox_sites_dict

def match_sites_to_netbox(ubiquity_desc, netbox_sites_dict, config=None):
    """
    Match Ubiquity site to NetBox site using the site mapping configuration.

    :param ubiquity_desc: The description of the Ubiquity site.
    :param netbox_sites_dict: A dictionary mapping NetBox site names to site objects.
    :param config: Configuration dictionary loaded from config.yaml
    :return: The matched NetBox site, or None if no match is found.
    """
    # Get the corresponding NetBox site name from the mapping
    netbox_site_name = get_netbox_site_name(ubiquity_desc, config)
    logger.debug(f'Mapping Ubiquity site: "{ubiquity_desc}" -> "{netbox_site_name}"')
    
    # Look for exact match in NetBox sites
    if netbox_site_name in netbox_sites_dict:
        netbox_site = netbox_sites_dict[netbox_site_name]
        logger.debug(f'Matched Ubiquity site "{ubiquity_desc}" to NetBox site "{netbox_site.name}"')
        return netbox_site
    
    # If site mapping is enabled but no match found, provide more helpful message
    if config and 'UNIFI' in config and ('USE_SITE_MAPPING' in config['UNIFI'] and config['UNIFI']['USE_SITE_MAPPING'] or 
                                        'SITE_MAPPINGS' in config['UNIFI'] and config['UNIFI']['SITE_MAPPINGS']):
        logger.debug(f'No match found for Ubiquity site "{ubiquity_desc}". Add mapping in config.yaml or site_mapping.yaml.')
    else:
        logger.debug(f'No match found for Ubiquity site "{ubiquity_desc}". Enable site mapping in config.yaml if needed.')
    return None

def setup_logging(min_log_level=logging.INFO):
    """
    Sets up logging to separate files for each log level.
    Only logs from the specified `min_log_level` and above are saved in their respective files.
    Includes console logging for the same log levels.

    :param min_log_level: Minimum log level to log. Defaults to logging.INFO.
    """
    logs_dir = "logs"
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)

    if not os.access(logs_dir, os.W_OK):
        raise PermissionError(f"Cannot write to log directory: {logs_dir}")

    # Log files for each level
    log_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }

    # Create the root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Capture all log levels

    # Define a log format
    log_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    # Set up file handlers for each log level
    for level_name, level_value in log_levels.items():
        if level_value >= min_log_level:
            log_file = os.path.join(logs_dir, f"{level_name.lower()}.log")
            handler = logging.FileHandler(log_file)
            handler.setLevel(level_value)
            handler.setFormatter(log_format)

            # Add a filter so only logs of this specific level are captured
            handler.addFilter(lambda record, lv=level_value: record.levelno == lv)
            logger.addHandler(handler)

    # Set up console handler for logs at `min_log_level` and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(min_log_level)
    console_handler.setFormatter(log_format)
    logger.addHandler(console_handler)

    logging.info(f"Logging is set up. Minimum log level: {logging.getLevelName(min_log_level)}")

def load_config(config_path: str = "config/config.yaml") -> dict:
    """
    Reads the configuration from a YAML file.

    :param config_path: Path to the YAML configuration file.
    :return: A dictionary of the configuration.
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r") as file:
        try:
            config = yaml.safe_load(file)  # Use safe_load to avoid executing malicious YAML code
            return config
        except yaml.YAMLError as e:
            raise Exception(f"Error reading configuration file: {e}")
