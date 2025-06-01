"""
Configuration manager for the Discord Gameserver Notifier
Handles loading, validation and runtime updates of the YAML configuration.
"""

import os
import yaml
import ipaddress
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

class ConfigManager:
    # Default configuration values
    DEFAULT_CONFIG = {
        'network': {
            'scan_interval': 300,
            'timeout': 5,
            'scan_ranges': ['192.168.1.0/24']
        },
        'games': {
            'enabled': ['source']
        },
        'discord': {
            'webhook_url': None,
            'channel_id': None,
            'mentions': []
        },
        'database': {
            'path': './gameservers.db',
            'cleanup_after_fails': 5
        },
        'debugging': {
            'log_level': 'INFO',
            'log_to_file': True,
            'log_file': './notifier.log'
        }
    }

    def __init__(self, config_path: str = 'config/config.yaml'):
        """Initialize the ConfigManager with a path to the config file."""
        self.config_path = config_path
        self.config = {}
        self.logger = logging.getLogger(__name__)
        self.load_config()

    def load_config(self) -> None:
        """Load and validate the YAML configuration file."""
        try:
            if not os.path.exists(self.config_path):
                self.logger.warning(f"Config file not found at {self.config_path}. Using default configuration.")
                self.config = self.DEFAULT_CONFIG.copy()
                return

            with open(self.config_path, 'r') as config_file:
                loaded_config = yaml.safe_load(config_file)

            # Merge loaded config with defaults
            self.config = self._merge_with_defaults(loaded_config)
            
            # Validate the configuration
            self._validate_config()
            
            self.logger.info("Configuration loaded and validated successfully")
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            raise

    def _merge_with_defaults(self, loaded_config: Dict[str, Any]) -> Dict[str, Any]:
        """Merge loaded configuration with default values."""
        if loaded_config is None:
            return self.DEFAULT_CONFIG.copy()

        merged = self.DEFAULT_CONFIG.copy()
        for section, values in loaded_config.items():
            if section in merged:
                if isinstance(merged[section], dict) and isinstance(values, dict):
                    merged[section].update(values)
                else:
                    merged[section] = values
            else:
                merged[section] = values
        return merged

    def _validate_config(self) -> None:
        """Validate all configuration sections."""
        self._validate_network_config()
        self._validate_discord_config()
        self._validate_database_config()
        self._validate_debugging_config()

    def _validate_network_config(self) -> None:
        """Validate network configuration section."""
        network = self.config.get('network', {})
        
        # Validate scan ranges
        scan_ranges = network.get('scan_ranges', [])
        if not scan_ranges:
            raise ValueError("At least one network scan range must be specified")
        
        for net_range in scan_ranges:
            try:
                ipaddress.ip_network(net_range)
            except ValueError as e:
                raise ValueError(f"Invalid network range '{net_range}': {str(e)}")

        # Validate intervals and timeouts
        if not isinstance(network.get('scan_interval', 300), (int, float)) or network['scan_interval'] <= 0:
            raise ValueError("scan_interval must be a positive number")
        
        if not isinstance(network.get('timeout', 5), (int, float)) or network['timeout'] <= 0:
            raise ValueError("timeout must be a positive number")

    def _validate_discord_config(self) -> None:
        """Validate Discord configuration section."""
        discord = self.config.get('discord', {})
        
        # Validate webhook URL
        webhook_url = discord.get('webhook_url')
        if webhook_url:
            parsed_url = urlparse(webhook_url)
            if not all([parsed_url.scheme, parsed_url.netloc]) or 'discord.com' not in parsed_url.netloc:
                raise ValueError("Invalid Discord webhook URL")

        # Validate channel ID
        channel_id = discord.get('channel_id')
        if channel_id and not str(channel_id).isdigit():
            raise ValueError("Discord channel ID must be a numeric string")

    def _validate_database_config(self) -> None:
        """Validate database configuration section."""
        database = self.config.get('database', {})
        
        # Validate database path
        db_path = database.get('path', '')
        if not db_path:
            raise ValueError("Database path must be specified")
        
        # Validate cleanup threshold
        cleanup_after = database.get('cleanup_after_fails', 5)
        if not isinstance(cleanup_after, int) or cleanup_after < 1:
            raise ValueError("cleanup_after_fails must be a positive integer")

    def _validate_debugging_config(self) -> None:
        """Validate debugging configuration section."""
        debugging = self.config.get('debugging', {})
        
        # Validate log level
        valid_log_levels = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
        log_level = debugging.get('log_level', 'INFO').upper()
        if log_level not in valid_log_levels:
            raise ValueError(f"Invalid log level. Must be one of: {', '.join(valid_log_levels)}")

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key."""
        return self.config.get(key, default)

    def update_config(self, new_config: Dict[str, Any]) -> None:
        """Update configuration at runtime."""
        # Store the old config in case validation fails
        old_config = self.config.copy()
        
        try:
            # Merge new config with current config
            self.config = self._merge_with_defaults(new_config)
            # Validate the new configuration
            self._validate_config()
            self.logger.info("Configuration updated successfully")
        except Exception as e:
            # Restore old config if validation fails
            self.config = old_config
            self.logger.error(f"Failed to update configuration: {str(e)}")
            raise

    def save_config(self) -> None:
        """Save the current configuration to file."""
        try:
            with open(self.config_path, 'w') as config_file:
                yaml.safe_dump(self.config, config_file, default_flow_style=False)
            self.logger.info(f"Configuration saved to {self.config_path}")
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {str(e)}")
            raise 