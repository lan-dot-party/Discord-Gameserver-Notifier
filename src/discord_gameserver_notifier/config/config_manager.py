"""
Configuration manager for the Discord Gameserver Notifier
Handles loading, validation and runtime updates of the YAML configuration.
"""

import os
import yaml
import ipaddress
import logging
import argparse
import sys
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
            'mentions': [],
            'game_mentions': {}
        },
        'database': {
            'path': 'auto',  # Auto-detect based on environment
            'cleanup_after_fails': 5
        },
        'debugging': {
            'log_level': 'INFO',
            'log_to_file': True,
            'log_file': 'auto'  # Auto-detect based on environment
        }
    }

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the ConfigManager with automatic config path resolution.
        
        Args:
            config_path: Optional explicit path to config file. If None, uses fallback search order.
        """
        self.config_path = config_path or self._resolve_config_path()
        self.config = {}
        self.logger = logging.getLogger(__name__)
        self.load_config()

    def _resolve_config_path(self) -> str:
        """
        Resolve configuration file path using fallback search order:
        1. CLI argument --config <path>
        2. Environment variable DGN_CONFIG
        3. System-wide config: /etc/dgn/config.yaml
        4. User config: $XDG_CONFIG_HOME/dgn/config.yaml or ~/.config/dgn/config.yaml
        5. Repository fallback: config/config.yaml
        
        Returns:
            str: Path to configuration file to use
        """
        # 1. Check CLI arguments (only if we're being called from main)
        cli_config = self._get_cli_config_path()
        if cli_config and os.path.exists(cli_config):
            return cli_config
        
        # 2. Check environment variable
        env_config = os.environ.get('DGN_CONFIG')
        if env_config and os.path.exists(env_config):
            return env_config
        
        # 3. System-wide config
        system_config = '/etc/dgn/config.yaml'
        if os.path.exists(system_config):
            return system_config
        
        # 4. User config directory
        user_config = self._get_user_config_path()
        if user_config and os.path.exists(user_config):
            return user_config
        
        # 5. Repository fallback
        repo_config = 'config/config.yaml'
        return repo_config

    def _get_cli_config_path(self) -> Optional[str]:
        """
        Extract --config argument from command line if present.
        
        Returns:
            Optional[str]: Config path from CLI argument or None
        """
        try:
            # Create a temporary parser just to extract --config
            parser = argparse.ArgumentParser(add_help=False)
            parser.add_argument('--config', type=str, help='Path to configuration file')
            
            # Parse known args to avoid conflicts with other arguments
            args, _ = parser.parse_known_args()
            return args.config
        except:
            # If parsing fails, return None (no CLI config specified)
            return None

    def _get_user_config_path(self) -> Optional[str]:
        """
        Get user configuration directory path.
        
        Returns:
            Optional[str]: User config path or None
        """
        # Check XDG_CONFIG_HOME first
        xdg_config_home = os.environ.get('XDG_CONFIG_HOME')
        if xdg_config_home:
            return os.path.join(xdg_config_home, 'dgn', 'config.yaml')
        
        # Fall back to ~/.config
        home_dir = os.path.expanduser('~')
        if home_dir and home_dir != '~':  # Make sure expansion worked
            return os.path.join(home_dir, '.config', 'dgn', 'config.yaml')
        
        return None

    def get_config_search_paths(self) -> List[str]:
        """
        Get list of all configuration paths that were checked (for debugging).
        
        Returns:
            List[str]: List of configuration paths in search order
        """
        paths = []
        
        # CLI argument
        cli_config = self._get_cli_config_path()
        if cli_config:
            paths.append(f"CLI --config: {cli_config}")
        
        # Environment variable
        env_config = os.environ.get('DGN_CONFIG')
        if env_config:
            paths.append(f"Environment DGN_CONFIG: {env_config}")
        
        # System-wide
        paths.append("System-wide: /etc/dgn/config.yaml")
        
        # User config
        user_config = self._get_user_config_path()
        if user_config:
            paths.append(f"User config: {user_config}")
        
        # Repository fallback
        paths.append("Repository fallback: config/config.yaml")
        
        return paths

    def _apply_environment_overrides(self) -> None:
        """Apply environment variable overrides and auto-detect deployment environment."""
        # Auto-detect deployment environment
        self._auto_detect_deployment_paths()
        
        # Override database path from environment
        db_path_env = os.environ.get('DGN_DATABASE_PATH')
        if db_path_env:
            self.config['database']['path'] = db_path_env
            self.logger.debug(f"Database path overridden from environment: {db_path_env}")
        
        # Override log file path from environment
        log_file_env = os.environ.get('DGN_LOG_FILE')
        if log_file_env:
            self.config['debugging']['log_file'] = log_file_env
            self.logger.debug(f"Log file path overridden from environment: {log_file_env}")
        
        # Override Discord webhook URL from environment
        webhook_url_env = os.environ.get('DGN_DISCORD_WEBHOOK_URL')
        if webhook_url_env:
            self.config['discord']['webhook_url'] = webhook_url_env
            self.logger.debug("Discord webhook URL overridden from environment")
        
        # Override Discord channel ID from environment
        channel_id_env = os.environ.get('DGN_DISCORD_CHANNEL_ID')
        if channel_id_env:
            self.config['discord']['channel_id'] = channel_id_env
            self.logger.debug(f"Discord channel ID overridden from environment: {channel_id_env}")

    def _auto_detect_deployment_paths(self) -> None:
        """Auto-detect deployment environment and set appropriate paths."""
        # Check if database path is set to "auto"
        if self.config.get('database', {}).get('path') == 'auto':
            if self._is_production_environment():
                self.config['database']['path'] = '/var/lib/dgn/gameservers.db'
                self.logger.debug("Auto-detected production environment - using /var/lib/dgn/gameservers.db")
            else:
                self.config['database']['path'] = './gameservers.db'
                self.logger.debug("Auto-detected development environment - using ./gameservers.db")
        
        # Check if log file path is set to "auto"
        if self.config.get('debugging', {}).get('log_file') == 'auto':
            if self._is_production_environment():
                self.config['debugging']['log_file'] = '/var/log/dgn/notifier.log'
                self.logger.debug("Auto-detected production environment - using /var/log/dgn/notifier.log")
            else:
                self.config['debugging']['log_file'] = './notifier.log'
                self.logger.debug("Auto-detected development environment - using ./notifier.log")

    def _is_production_environment(self) -> bool:
        """
        Detect if we're running in a production environment.
        
        Returns:
            bool: True if production environment is detected
        """
        # Check for systemd service indicators
        if os.environ.get('INVOCATION_ID'):  # systemd sets this
            return True
        
        # Check if we're running from the system-wide config location
        if self.config_path == '/etc/dgn/config.yaml':
            return True
        
        # Check if the systemd service directories exist
        production_dirs = ['/var/lib/dgn', '/var/log/dgn', '/etc/dgn']
        if all(os.path.exists(d) for d in production_dirs):
            return True
        
        # Check if we're running as a system user (not root, not regular user)
        try:
            import pwd
            current_user = pwd.getpwuid(os.getuid()).pw_name
            if current_user == 'dgn':  # Service user
                return True
        except:
            pass
        
        return False

    def load_config(self) -> None:
        """Load and validate the YAML configuration file."""
        try:
            if not os.path.exists(self.config_path):
                self.logger.warning(f"Config file not found at {self.config_path}. Using default configuration.")
                # Log the search paths for debugging
                search_paths = self.get_config_search_paths()
                self.logger.debug(f"Config search order was: {search_paths}")
                self.config = self.DEFAULT_CONFIG.copy()
                return

            with open(self.config_path, 'r') as config_file:
                loaded_config = yaml.safe_load(config_file)

            # Merge loaded config with defaults
            self.config = self._merge_with_defaults(loaded_config)
            
            # Validate the configuration
            self._validate_config()
            
            # Override paths from environment variables if set (useful for service deployment)
            self._apply_environment_overrides()
            
            self.logger.info(f"Configuration loaded successfully from: {self.config_path}")
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

        # Validate game_mentions
        game_mentions = discord.get('game_mentions', {})
        for game_name, mentions in game_mentions.items():
            if not isinstance(mentions, list):
                raise ValueError(f"game_mentions for '{game_name}' must be a list of mentions")
            for mention in mentions:
                if not isinstance(mention, str):
                    raise ValueError(f"Each mention in game_mentions for '{game_name}' must be a string")

    def _validate_database_config(self) -> None:
        """Validate database configuration section."""
        database = self.config.get('database', {})
        
        # Validate database path
        db_path = database.get('path', '')
        if not db_path:
            raise ValueError("Database path must be specified")
        # "auto" is valid - it will be resolved later
        
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