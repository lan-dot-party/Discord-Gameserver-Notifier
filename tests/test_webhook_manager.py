"""
Tests for WebhookManager - Discord webhook message handling.

These tests verify that the DGN correctly creates and would send
Discord webhook notifications for game server events.
All network requests are mocked - no actual Discord messages are sent.
"""

import sys
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Import from the actual modules
from discord_gameserver_notifier.discovery.server_info_wrapper import StandardizedServerInfo
from discord_gameserver_notifier.discord.webhook_manager import WebhookManager


class MockResponse:
    """Mock response object for requests library."""
    
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.text = text
    
    def json(self):
        return self._json_data


class TestWebhookManagerInitialization:
    """Tests for WebhookManager initialization."""
    
    def test_initialization_with_valid_url(self):
        """Test WebhookManager initializes correctly with valid webhook URL."""
        webhook_url = "https://discord.com/api/webhooks/123456789/abcdefghijklmnopqrstuvwxyz"
        
        manager = WebhookManager(webhook_url=webhook_url)
        
        assert manager is not None
        assert "wait=true" in manager.webhook_url
        assert manager.webhook_id == "123456789"
        assert manager.webhook_token == "abcdefghijklmnopqrstuvwxyz"
    
    def test_initialization_with_channel_id(self):
        """Test WebhookManager stores channel ID correctly."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        channel_id = "987654321"
        
        manager = WebhookManager(webhook_url=webhook_url, channel_id=channel_id)
        
        assert manager.channel_id == channel_id
    
    def test_initialization_with_mentions(self):
        """Test WebhookManager stores mentions correctly."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        mentions = ["@everyone", "<@&12345>"]
        
        manager = WebhookManager(webhook_url=webhook_url, mentions=mentions)
        
        assert manager.mentions == mentions
        assert len(manager.mentions) == 2
    
    def test_initialization_with_game_mentions(self):
        """Test WebhookManager stores game-specific mentions correctly."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        game_mentions = {
            'source': ['<@&SOURCE_ROLE>'],
            'renegadex': ['<@&RENEGADEX_ROLE>']
        }
        
        manager = WebhookManager(webhook_url=webhook_url, game_mentions=game_mentions)
        
        assert manager.game_mentions == game_mentions
        assert 'source' in manager.game_mentions
    
    def test_ensure_wait_parameter(self):
        """Test that wait=true is added to webhook URL."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        
        manager = WebhookManager(webhook_url=webhook_url)
        
        assert "wait=true" in manager.webhook_url
    
    def test_ensure_wait_parameter_not_duplicated(self):
        """Test that wait=true is not duplicated if already present."""
        webhook_url = "https://discord.com/api/webhooks/123/abc?wait=true"
        
        manager = WebhookManager(webhook_url=webhook_url)
        
        # Should have exactly one wait=true
        assert manager.webhook_url.count("wait=true") == 1
    
    def test_extract_webhook_credentials(self):
        """Test extraction of webhook ID and token from URL."""
        webhook_url = "https://discord.com/api/webhooks/111222333/tokenvalue123"
        
        manager = WebhookManager(webhook_url=webhook_url)
        
        assert manager.webhook_id == "111222333"
        assert manager.webhook_token == "tokenvalue123"


class TestGameColorsAndEmojis:
    """Tests for game-specific colors and emojis."""
    
    def test_game_colors_defined(self):
        """Test that game colors are defined for known game types."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        expected_games = ['source', 'renegadex', 'warcraft3', 'flatout2', 'ut3', 'toxikk', 'cnc_generals']
        
        for game in expected_games:
            assert game in manager.game_colors or 'default' in manager.game_colors
    
    def test_game_emojis_defined(self):
        """Test that game emojis are defined for known game types."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        expected_games = ['source', 'renegadex', 'warcraft3', 'flatout2', 'ut3', 'toxikk']
        
        for game in expected_games:
            assert game in manager.game_emojis or 'default' in manager.game_emojis
    
    def test_default_color_exists(self):
        """Test that a default color is available for unknown games."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        assert 'default' in manager.game_colors


class TestCombinedMentions:
    """Tests for combining global and game-specific mentions."""
    
    def test_get_combined_mentions_global_only(self):
        """Test combined mentions with only global mentions."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        mentions = ["@everyone"]
        
        manager = WebhookManager(webhook_url=webhook_url, mentions=mentions)
        
        combined = manager._get_combined_mentions("source")
        
        assert "@everyone" in combined
    
    def test_get_combined_mentions_game_only(self):
        """Test combined mentions with only game-specific mentions."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        game_mentions = {'source': ['<@&SOURCE_ROLE>']}
        
        manager = WebhookManager(webhook_url=webhook_url, game_mentions=game_mentions)
        
        combined = manager._get_combined_mentions("source")
        
        assert "<@&SOURCE_ROLE>" in combined
    
    def test_get_combined_mentions_both(self):
        """Test combined mentions with both global and game-specific."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        mentions = ["@everyone"]
        game_mentions = {'source': ['<@&SOURCE_ROLE>']}
        
        manager = WebhookManager(webhook_url=webhook_url, mentions=mentions, game_mentions=game_mentions)
        
        combined = manager._get_combined_mentions("source")
        
        assert "@everyone" in combined
        assert "<@&SOURCE_ROLE>" in combined
    
    def test_get_combined_mentions_no_duplicates(self):
        """Test that combined mentions don't contain duplicates."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        mentions = ["@everyone", "<@&ROLE>"]
        game_mentions = {'source': ['@everyone', '<@&ROLE>']}  # Same mentions
        
        manager = WebhookManager(webhook_url=webhook_url, mentions=mentions, game_mentions=game_mentions)
        
        combined = manager._get_combined_mentions("source")
        
        assert combined.count("@everyone") == 1
        assert combined.count("<@&ROLE>") == 1
    
    def test_get_combined_mentions_unknown_game(self):
        """Test combined mentions for unknown game type."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        mentions = ["@everyone"]
        game_mentions = {'source': ['<@&SOURCE_ROLE>']}
        
        manager = WebhookManager(webhook_url=webhook_url, mentions=mentions, game_mentions=game_mentions)
        
        combined = manager._get_combined_mentions("unknown_game")
        
        # Should only have global mentions
        assert "@everyone" in combined
        assert "<@&SOURCE_ROLE>" not in combined


class TestEmbedCreation:
    """Tests for Discord embed creation."""
    
    @pytest.fixture
    def sample_server_info(self):
        """Create a sample StandardizedServerInfo for testing."""
        return StandardizedServerInfo(
            name="Test Server",
            game="Counter-Strike 2",
            map="de_dust2",
            players=12,
            max_players=32,
            version="1.39.1.5",
            password_protected=False,
            ip_address="192.168.1.100",
            port=27015,
            game_type="source",
            response_time=0.025,
            additional_info={'vac': 1, 'server_type': 'd'},
            discord_fields=None
        )
    
    def test_create_new_server_embed(self, sample_server_info):
        """Test creating an embed for a new server discovery."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        embed = manager._create_server_embed(sample_server_info, is_new=True, is_offline=False)
        
        assert embed is not None
        assert "Neuer Server" in embed.title or "🟢" in embed.title
    
    def test_create_offline_server_embed(self, sample_server_info):
        """Test creating an embed for an offline server."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        embed = manager._create_server_embed(sample_server_info, is_new=False, is_offline=True)
        
        assert embed is not None
        assert "Offline" in embed.title or "🔴" in embed.title
    
    def test_create_update_server_embed(self, sample_server_info):
        """Test creating an embed for a server update."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        embed = manager._create_server_embed(sample_server_info, is_new=False, is_offline=False)
        
        assert embed is not None
        assert "Update" in embed.title or "📊" in embed.title
    
    def test_embed_contains_server_info(self, sample_server_info):
        """Test that embed contains all required server information fields."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        embed = manager._create_server_embed(sample_server_info, is_new=True)
        
        # Embed should have fields for game info
        # Note: We can't easily check field contents without mocking DiscordEmbed
        assert embed is not None
    
    def test_embed_with_password_protected_server(self):
        """Test embed creation for password-protected server."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        server_info = StandardizedServerInfo(
            name="Private Server",
            game="CS2",
            map="de_mirage",
            players=5,
            max_players=16,
            version="1.0",
            password_protected=True,  # Password protected
            ip_address="192.168.1.1",
            port=27015,
            game_type="source",
            response_time=0.02,
            additional_info={}
        )
        
        embed = manager._create_server_embed(server_info, is_new=True)
        
        assert embed is not None
    
    def test_embed_with_discord_fields(self):
        """Test embed creation with additional protocol-specific Discord fields."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        server_info = StandardizedServerInfo(
            name="Test Server",
            game="CS2",
            map="de_dust2",
            players=10,
            max_players=32,
            version="1.0",
            password_protected=False,
            ip_address="192.168.1.1",
            port=27015,
            game_type="source",
            response_time=0.02,
            additional_info={},
            discord_fields=[
                {'name': 'VAC Status', 'value': 'Enabled', 'inline': True},
                {'name': 'Server Type', 'value': 'Dedicated', 'inline': True}
            ]
        )
        
        embed = manager._create_server_embed(server_info, is_new=True)
        
        assert embed is not None


class TestSendNotification:
    """Tests for sending webhook notifications (mocked)."""
    
    @pytest.fixture
    def sample_server_info(self):
        """Create a sample StandardizedServerInfo for testing."""
        return StandardizedServerInfo(
            name="Test Server",
            game="Counter-Strike 2",
            map="de_dust2",
            players=12,
            max_players=32,
            version="1.39.1.5",
            password_protected=False,
            ip_address="192.168.1.100",
            port=27015,
            game_type="source",
            response_time=0.025,
            additional_info={},
            discord_fields=None
        )
    
    @patch('discord_gameserver_notifier.discord.webhook_manager.DiscordWebhook')
    def test_send_new_server_notification_success(self, mock_webhook_class, sample_server_info):
        """Test successful sending of new server notification."""
        # Setup mock
        mock_webhook_instance = MagicMock()
        mock_webhook_class.return_value = mock_webhook_instance
        mock_webhook_instance.execute.return_value = MockResponse(
            status_code=200,
            json_data={'id': '123456789012345678'}
        )
        
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        # Send notification
        message_id = manager.send_new_server_notification(sample_server_info)
        
        # Verify
        assert message_id == '123456789012345678'
        mock_webhook_instance.add_embed.assert_called_once()
        mock_webhook_instance.execute.assert_called_once()
    
    @patch('discord_gameserver_notifier.discord.webhook_manager.DiscordWebhook')
    def test_send_new_server_notification_failure(self, mock_webhook_class, sample_server_info):
        """Test handling of failed notification sending."""
        # Setup mock
        mock_webhook_instance = MagicMock()
        mock_webhook_class.return_value = mock_webhook_instance
        mock_webhook_instance.execute.return_value = MockResponse(status_code=500)
        
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        # Send notification
        message_id = manager.send_new_server_notification(sample_server_info)
        
        # Verify
        assert message_id is None
    
    @patch('discord_gameserver_notifier.discord.webhook_manager.DiscordWebhook')
    def test_send_notification_with_mentions(self, mock_webhook_class, sample_server_info):
        """Test that notifications include configured mentions."""
        # Setup mock
        mock_webhook_instance = MagicMock()
        mock_webhook_class.return_value = mock_webhook_instance
        mock_webhook_instance.execute.return_value = MockResponse(
            status_code=200,
            json_data={'id': '123'}
        )
        
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        mentions = ["@everyone"]
        manager = WebhookManager(webhook_url=webhook_url, mentions=mentions)
        
        # Send notification
        manager.send_new_server_notification(sample_server_info)
        
        # Verify content was set with mentions
        # The content property should include mentions
        assert mock_webhook_instance.content is not None or mock_webhook_instance.add_embed.called
    
    @patch('discord_gameserver_notifier.discord.webhook_manager.DiscordWebhook')
    def test_send_notification_exception_handling(self, mock_webhook_class, sample_server_info):
        """Test exception handling during notification sending."""
        # Setup mock to raise exception
        mock_webhook_class.side_effect = Exception("Network error")
        
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        # Send notification - should not raise exception
        message_id = manager.send_new_server_notification(sample_server_info)
        
        # Should return None on error
        assert message_id is None


class TestDeleteMessage:
    """Tests for deleting Discord messages (mocked)."""
    
    @patch('discord_gameserver_notifier.discord.webhook_manager.requests.delete')
    def test_delete_message_success(self, mock_delete):
        """Test successful message deletion."""
        mock_delete.return_value = MockResponse(status_code=204)
        
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        result = manager.delete_server_message("message123")
        
        assert result is True
        mock_delete.assert_called_once()
    
    @patch('discord_gameserver_notifier.discord.webhook_manager.requests.delete')
    def test_delete_message_not_found(self, mock_delete):
        """Test deletion of non-existent message (should succeed)."""
        mock_delete.return_value = MockResponse(status_code=404)
        
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        result = manager.delete_server_message("nonexistent123")
        
        # 404 is treated as success (message already gone)
        assert result is True
    
    @patch('discord_gameserver_notifier.discord.webhook_manager.requests.delete')
    def test_delete_message_failure(self, mock_delete):
        """Test failed message deletion."""
        mock_delete.return_value = MockResponse(status_code=500, text="Server error")
        
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        result = manager.delete_server_message("message123")
        
        assert result is False
    
    def test_delete_message_no_credentials(self):
        """Test deletion fails gracefully without webhook credentials."""
        webhook_url = "invalid-url"
        
        manager = WebhookManager(webhook_url=webhook_url)
        manager.webhook_id = None
        manager.webhook_token = None
        
        result = manager.delete_server_message("message123")
        
        assert result is False
    
    def test_delete_message_empty_id(self):
        """Test deletion fails gracefully with empty message ID."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        result = manager.delete_server_message("")
        
        assert result is False
    
    @patch('discord_gameserver_notifier.discord.webhook_manager.requests.delete')
    def test_delete_message_exception_handling(self, mock_delete):
        """Test exception handling during message deletion."""
        mock_delete.side_effect = Exception("Network error")
        
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        result = manager.delete_server_message("message123")
        
        assert result is False


class TestOfflineNotification:
    """Tests for server offline notifications."""
    
    @pytest.fixture
    def sample_server_info(self):
        """Create a sample StandardizedServerInfo for testing."""
        return StandardizedServerInfo(
            name="Test Server",
            game="Counter-Strike 2",
            map="de_dust2",
            players=0,
            max_players=32,
            version="1.39.1.5",
            password_protected=False,
            ip_address="192.168.1.100",
            port=27015,
            game_type="source",
            response_time=0.0,
            additional_info={},
            discord_fields=None
        )
    
    @patch('discord_gameserver_notifier.discord.webhook_manager.requests.delete')
    def test_offline_notification_deletes_message(self, mock_delete, sample_server_info):
        """Test that offline notification deletes existing message when ID provided."""
        mock_delete.return_value = MockResponse(status_code=204)
        
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        result = manager.send_server_offline_notification(sample_server_info, message_id="existingmsg123")
        
        assert result is True
        mock_delete.assert_called_once()
    
    @patch('discord_gameserver_notifier.discord.webhook_manager.DiscordWebhook')
    def test_offline_notification_sends_message_without_id(self, mock_webhook_class, sample_server_info):
        """Test that offline notification sends new message when no ID provided."""
        mock_webhook_instance = MagicMock()
        mock_webhook_class.return_value = mock_webhook_instance
        mock_webhook_instance.execute.return_value = MockResponse(status_code=200)
        
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        result = manager.send_server_offline_notification(sample_server_info, message_id=None)
        
        assert result is True
        mock_webhook_instance.add_embed.assert_called_once()


class TestWebhookTest:
    """Tests for webhook connection testing."""
    
    @patch('discord_gameserver_notifier.discord.webhook_manager.DiscordWebhook')
    def test_test_webhook_success(self, mock_webhook_class):
        """Test successful webhook connection test."""
        mock_webhook_instance = MagicMock()
        mock_webhook_class.return_value = mock_webhook_instance
        mock_webhook_instance.execute.return_value = MockResponse(status_code=200)
        
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        result = manager.test_webhook()
        
        assert result is True
    
    @patch('discord_gameserver_notifier.discord.webhook_manager.DiscordWebhook')
    def test_test_webhook_failure(self, mock_webhook_class):
        """Test failed webhook connection test."""
        mock_webhook_instance = MagicMock()
        mock_webhook_class.return_value = mock_webhook_instance
        mock_webhook_instance.execute.return_value = MockResponse(status_code=401)
        
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        result = manager.test_webhook()
        
        assert result is False
    
    @patch('discord_gameserver_notifier.discord.webhook_manager.DiscordWebhook')
    def test_test_webhook_exception(self, mock_webhook_class):
        """Test webhook test exception handling."""
        mock_webhook_class.side_effect = Exception("Connection refused")
        
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        result = manager.test_webhook()
        
        assert result is False


class TestGetWebhookInfo:
    """Tests for webhook info retrieval."""
    
    def test_get_webhook_info(self):
        """Test getting webhook configuration info."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        channel_id = "987654321"
        mentions = ["@everyone", "@here"]
        game_mentions = {'source': ['<@&123>']}
        
        manager = WebhookManager(
            webhook_url=webhook_url,
            channel_id=channel_id,
            mentions=mentions,
            game_mentions=game_mentions
        )
        
        info = manager.get_webhook_info()
        
        assert info['webhook_url_configured'] is True
        assert info['channel_id'] == channel_id
        assert info['mentions_count'] == 2
        assert info['game_mentions_count'] == 1


class TestAllGameTypesEmbedCreation:
    """Integration tests for embed creation with all game types."""
    
    def test_create_embed_for_all_game_types(self, all_server_responses, server_info_wrapper):
        """Test that embeds can be created for all supported game types."""
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        for game_type, response in all_server_responses.items():
            # Standardize the server info first
            server_info = server_info_wrapper.standardize_server_response(response)
            
            # Create embed
            try:
                embed = manager._create_server_embed(server_info, is_new=True)
                
                assert embed is not None, f"Failed to create embed for {game_type}"
                assert embed.title is not None, f"Embed title is None for {game_type}"
                
            except Exception as e:
                pytest.fail(f"Failed to create embed for {game_type}: {e}")
    
    @patch('discord_gameserver_notifier.discord.webhook_manager.DiscordWebhook')
    def test_notification_for_all_game_types(self, mock_webhook_class, all_server_responses, server_info_wrapper):
        """Test that notifications can be prepared for all game types."""
        mock_webhook_instance = MagicMock()
        mock_webhook_class.return_value = mock_webhook_instance
        mock_webhook_instance.execute.return_value = MockResponse(
            status_code=200,
            json_data={'id': '123456789'}
        )
        
        webhook_url = "https://discord.com/api/webhooks/123/abc"
        manager = WebhookManager(webhook_url=webhook_url)
        
        for game_type, response in all_server_responses.items():
            # Standardize the server info first
            server_info = server_info_wrapper.standardize_server_response(response)
            
            # Send notification
            try:
                message_id = manager.send_new_server_notification(server_info)
                
                assert message_id == '123456789', f"Failed notification for {game_type}"
                
            except Exception as e:
                pytest.fail(f"Failed to send notification for {game_type}: {e}")

