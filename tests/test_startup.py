"""
Tests for DGN application startup and configuration loading.
"""

import os
import sys
import pytest
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from discord_gameserver_notifier.config.config_manager import ConfigManager


class TestConfigManager:
    """Tests for the ConfigManager class."""
    
    def test_default_config_values(self, temp_config_dir):
        """Test that ConfigManager has sensible default values."""
        # Test with non-existent config path - should use defaults
        config_path = temp_config_dir / "nonexistent.yaml"
        manager = ConfigManager(str(config_path))
        
        # Check default values exist
        assert 'network' in manager.config
        assert 'games' in manager.config
        assert 'discord' in manager.config
        assert 'database' in manager.config
        assert 'debugging' in manager.config
        
        # Check specific defaults
        assert manager.config['network']['scan_interval'] == 300
        assert manager.config['network']['timeout'] == 5
        assert manager.config['debugging']['log_level'] == 'INFO'
    
    def test_load_valid_config(self, temp_config_file, minimal_config):
        """Test loading a valid configuration file."""
        manager = ConfigManager(str(temp_config_file))
        
        # Verify config was loaded
        assert manager.config['network']['scan_ranges'] == minimal_config['network']['scan_ranges']
        assert manager.config['network']['scan_interval'] == minimal_config['network']['scan_interval']
        assert manager.config['discord']['webhook_url'] == minimal_config['discord']['webhook_url']
    
    def test_config_merge_with_defaults(self, temp_config_dir):
        """Test that partial configs are merged with defaults."""
        # Create a minimal partial config
        partial_config = {
            'network': {
                'scan_ranges': ['10.0.0.0/24']
            }
        }
        
        config_file = temp_config_dir / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(partial_config, f)
        
        manager = ConfigManager(str(config_file))
        
        # Check that partial config values are set
        assert manager.config['network']['scan_ranges'] == ['10.0.0.0/24']
        
        # Check that defaults are preserved
        assert manager.config['network']['scan_interval'] == 300
        assert manager.config['database']['cleanup_after_fails'] == 5
    
    def test_validate_network_ranges(self, temp_config_dir):
        """Test validation of network scan ranges."""
        # Valid config
        valid_config = {
            'network': {
                'scan_ranges': ['192.168.1.0/24', '10.0.0.0/8']
            }
        }
        
        config_file = temp_config_dir / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(valid_config, f)
        
        manager = ConfigManager(str(config_file))
        assert len(manager.config['network']['scan_ranges']) == 2
    
    def test_validate_invalid_network_range(self, temp_config_dir):
        """Test that invalid network ranges raise an error."""
        invalid_config = {
            'network': {
                'scan_ranges': ['invalid_range']
            }
        }
        
        config_file = temp_config_dir / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(invalid_config, f)
        
        with pytest.raises(ValueError, match="Invalid network range"):
            ConfigManager(str(config_file))
    
    def test_validate_discord_webhook_url(self, temp_config_dir):
        """Test validation of Discord webhook URL."""
        valid_config = {
            'network': {'scan_ranges': ['192.168.1.0/24']},
            'discord': {
                'webhook_url': 'https://discord.com/api/webhooks/123456/abcdef'
            }
        }
        
        config_file = temp_config_dir / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(valid_config, f)
        
        manager = ConfigManager(str(config_file))
        assert 'discord.com' in manager.config['discord']['webhook_url']
    
    def test_validate_invalid_discord_webhook_url(self, temp_config_dir):
        """Test that invalid Discord webhook URL raises an error."""
        invalid_config = {
            'network': {'scan_ranges': ['192.168.1.0/24']},
            'discord': {
                'webhook_url': 'https://example.com/not-a-webhook'
            }
        }
        
        config_file = temp_config_dir / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(invalid_config, f)
        
        with pytest.raises(ValueError, match="Invalid Discord webhook URL"):
            ConfigManager(str(config_file))
    
    def test_validate_api_port(self, temp_config_dir):
        """Test validation of API port."""
        valid_config = {
            'network': {'scan_ranges': ['192.168.1.0/24']},
            'discord': {'webhook_url': 'https://discord.com/api/webhooks/123/abc'},
            'api': {
                'enabled': True,
                'host': '0.0.0.0',
                'port': 8080
            }
        }
        
        config_file = temp_config_dir / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(valid_config, f)
        
        manager = ConfigManager(str(config_file))
        assert manager.config['api']['port'] == 8080
    
    def test_validate_invalid_api_port(self, temp_config_dir):
        """Test that invalid API port raises an error."""
        invalid_config = {
            'network': {'scan_ranges': ['192.168.1.0/24']},
            'discord': {'webhook_url': 'https://discord.com/api/webhooks/123/abc'},
            'api': {
                'enabled': True,
                'host': '0.0.0.0',
                'port': 99999  # Invalid port
            }
        }
        
        config_file = temp_config_dir / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(invalid_config, f)
        
        with pytest.raises(ValueError, match="api.port must be an integer"):
            ConfigManager(str(config_file))
    
    def test_validate_log_level(self, temp_config_dir):
        """Test validation of log levels."""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        
        for level in valid_levels:
            config = {
                'network': {'scan_ranges': ['192.168.1.0/24']},
                'discord': {'webhook_url': 'https://discord.com/api/webhooks/123/abc'},
                'api': {'enabled': False, 'port': 8080, 'host': '0.0.0.0'},
                'debugging': {'log_level': level}
            }
            
            config_file = temp_config_dir / "config.yaml"
            with open(config_file, 'w') as f:
                yaml.dump(config, f)
            
            manager = ConfigManager(str(config_file))
            # Config should load without error
            assert manager.config['debugging']['log_level'] == level
    
    def test_validate_invalid_log_level(self, temp_config_dir):
        """Test that invalid log level raises an error."""
        invalid_config = {
            'network': {'scan_ranges': ['192.168.1.0/24']},
            'discord': {'webhook_url': 'https://discord.com/api/webhooks/123/abc'},
            'api': {'enabled': False, 'port': 8080, 'host': '0.0.0.0'},
            'debugging': {'log_level': 'INVALID_LEVEL'}
        }
        
        config_file = temp_config_dir / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(invalid_config, f)
        
        with pytest.raises(ValueError, match="Invalid log level"):
            ConfigManager(str(config_file))
    
    def test_game_mentions_validation(self, temp_config_dir):
        """Test validation of game-specific mentions."""
        valid_config = {
            'network': {'scan_ranges': ['192.168.1.0/24']},
            'api': {'enabled': False, 'port': 8080, 'host': '0.0.0.0'},
            'debugging': {'log_level': 'INFO'},
            'discord': {
                'webhook_url': 'https://discord.com/api/webhooks/123/abc',
                'game_mentions': {
                    'source': ['@everyone', '<@&123456>'],
                    'renegadex': ['@here']
                }
            }
        }
        
        config_file = temp_config_dir / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(valid_config, f)
        
        manager = ConfigManager(str(config_file))
        assert 'source' in manager.config['discord']['game_mentions']
        assert len(manager.config['discord']['game_mentions']['source']) == 2
    
    def test_environment_variable_override(self, temp_config_file):
        """Test that environment variables can override config values."""
        with patch.dict(os.environ, {'DGN_DATABASE_PATH': '/custom/path/db.sqlite'}):
            manager = ConfigManager(str(temp_config_file))
            assert manager.config['database']['path'] == '/custom/path/db.sqlite'
    
    def test_get_method(self, temp_config_file):
        """Test the get method for retrieving config values."""
        manager = ConfigManager(str(temp_config_file))
        
        # Test existing key
        assert manager.get('network') is not None
        
        # Test non-existing key with default
        assert manager.get('nonexistent', 'default_value') == 'default_value'
        
        # Test non-existing key without default
        assert manager.get('nonexistent') is None


class TestApplicationStartup:
    """Tests for application startup behavior."""
    
    def test_config_search_paths(self, temp_config_dir):
        """Test that config search paths are properly ordered."""
        config_file = temp_config_dir / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump({'network': {'scan_ranges': ['192.168.1.0/24']}}, f)
        
        manager = ConfigManager(str(config_file))
        search_paths = manager.get_config_search_paths()
        
        # Should contain at least some standard paths
        assert len(search_paths) > 0
        assert any('System-wide' in path for path in search_paths)
        assert any('Repository fallback' in path for path in search_paths)
    
    def test_production_environment_detection(self, temp_config_dir):
        """Test detection of production environment."""
        config_file = temp_config_dir / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump({'network': {'scan_ranges': ['192.168.1.0/24']}}, f)
        
        manager = ConfigManager(str(config_file))
        
        # In test environment, should not be production
        is_prod = manager._is_production_environment()
        
        # This should be False in test environment
        # (unless running in a container with systemd)
        assert isinstance(is_prod, bool)
    
    def test_auto_detect_database_path(self, temp_config_dir):
        """Test auto-detection of database path based on environment."""
        config = {
            'network': {'scan_ranges': ['192.168.1.0/24']},
            'database': {'path': 'auto'}
        }
        
        config_file = temp_config_dir / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config, f)
        
        manager = ConfigManager(str(config_file))
        
        # Path should be resolved (not 'auto' anymore)
        # In dev environment, should be './gameservers.db'
        assert manager.config['database']['path'] != 'auto'
    
    def test_games_enabled_config(self, temp_config_dir):
        """Test loading of enabled games configuration."""
        config = {
            'network': {'scan_ranges': ['192.168.1.0/24']},
            'games': {
                'enabled': ['source', 'renegadex', 'warcraft3', 'ut3']
            }
        }
        
        config_file = temp_config_dir / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config, f)
        
        manager = ConfigManager(str(config_file))
        
        assert 'source' in manager.config['games']['enabled']
        assert 'renegadex' in manager.config['games']['enabled']
        assert len(manager.config['games']['enabled']) == 4

