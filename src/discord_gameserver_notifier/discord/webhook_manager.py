"""
Discord webhook management and message handling
"""

import logging
import asyncio
import requests
from typing import Optional, Dict, Any
from discord_webhook import DiscordWebhook, DiscordEmbed
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..discovery.server_info_wrapper import StandardizedServerInfo


class WebhookManager:
    """
    Manages Discord webhook communications for game server notifications.
    Handles sending embeds for new server discoveries and server status updates.
    """
    
    def __init__(self, webhook_url: str, channel_id: Optional[str] = None, mentions: Optional[list] = None, game_mentions: Optional[dict] = None):
        """
        Initialize the WebhookManager.
        
        Args:
            webhook_url: Discord webhook URL
            channel_id: Optional Discord channel ID for reference
            mentions: Optional list of global mentions to include in messages
            game_mentions: Optional dictionary of game-specific mentions
        """
        # Automatically append ?wait=true to webhook URL for message ID retrieval
        self.webhook_url = self._ensure_wait_parameter(webhook_url)
        self.channel_id = channel_id
        self.mentions = mentions or []
        self.game_mentions = game_mentions or {}
        self.logger = logging.getLogger("GameServerNotifier.WebhookManager")
        
        # Extract webhook ID and token for message deletion
        self.webhook_id, self.webhook_token = self._extract_webhook_credentials(self.webhook_url)
        
        # Game-specific colors and emojis for embeds
        self.game_colors = {
            'source': 0xFF6600,      # Orange for Source Engine
            'renegadex': 0x00FF00,   # Green for RenegadeX
            'warcraft3': 0x0066CC,   # Blue for Warcraft 3
            'flatout2': 0xFF0000,    # Red for Flatout 2
            'ut3': 0x9932CC,         # Purple for Unreal Tournament 3
            'default': 0x7289DA      # Discord Blurple
        }
        
        self.game_emojis = {
            'source': '🎮',
            'renegadex': '⚔️',
            'warcraft3': '🏰',
            'flatout2': '🏎️',
            'ut3': '🔫',
            'default': '🎯'
        }
        
        self.logger.info(f"WebhookManager initialized for channel {channel_id}")
        self.logger.debug(f"Webhook URL configured with wait=true: {self.webhook_url}")
    
    def _ensure_wait_parameter(self, webhook_url: str) -> str:
        """
        Ensure the webhook URL has ?wait=true parameter for message ID retrieval.
        
        Args:
            webhook_url: Original webhook URL
            
        Returns:
            Webhook URL with ?wait=true parameter
        """
        parsed = urlparse(webhook_url)
        query_params = parse_qs(parsed.query)
        
        # Add wait=true parameter
        query_params['wait'] = ['true']
        
        # Reconstruct URL with updated query parameters
        new_query = urlencode(query_params, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        
        return urlunparse(new_parsed)
    
    def _extract_webhook_credentials(self, webhook_url: str) -> tuple[Optional[str], Optional[str]]:
        """
        Extract webhook ID and token from webhook URL for message deletion.
        
        Args:
            webhook_url: Discord webhook URL
            
        Returns:
            Tuple of (webhook_id, webhook_token)
        """
        try:
            parsed = urlparse(webhook_url)
            path_parts = parsed.path.strip('/').split('/')
            
            if len(path_parts) >= 4 and path_parts[0] == 'api' and path_parts[1] == 'webhooks':
                webhook_id = path_parts[2]
                webhook_token = path_parts[3]
                return webhook_id, webhook_token
            
        except Exception as e:
            self.logger.warning(f"Could not extract webhook credentials: {e}")
        
        return None, None
    
    def _get_combined_mentions(self, game_type: str) -> list:
        """
        Get combined mentions for a specific game type.
        Combines global mentions with game-specific mentions.
        
        Args:
            game_type: The game type (e.g., 'source', 'renegadex', etc.)
            
        Returns:
            List of combined mentions
        """
        combined_mentions = []
        
        # Add global mentions
        combined_mentions.extend(self.mentions)
        
        # Add game-specific mentions
        game_specific_mentions = self.game_mentions.get(game_type.lower(), [])
        combined_mentions.extend(game_specific_mentions)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_mentions = []
        for mention in combined_mentions:
            if mention not in seen:
                seen.add(mention)
                unique_mentions.append(mention)
        
        return unique_mentions
    
    def send_new_server_notification(self, server_info: StandardizedServerInfo) -> Optional[str]:
        """
        Send a Discord notification for a newly discovered game server.
        
        Args:
            server_info: Standardized server information
            
        Returns:
            Message ID if successful, None if failed
        """
        try:
            # Create the webhook
            webhook = DiscordWebhook(url=self.webhook_url)
            
            # Get combined mentions (global + game-specific)
            combined_mentions = self._get_combined_mentions(server_info.game_type)
            
            # Add mentions if any are configured
            if combined_mentions:
                mention_text = " ".join(combined_mentions)
                webhook.content = f"{mention_text} 🎉 **Neuer Gameserver im Netzwerk entdeckt!**"
            
            # Create embed for server information
            embed = self._create_server_embed(server_info, is_new=True)
            webhook.add_embed(embed)
            
            # Send the webhook
            response = webhook.execute()
            
            if response.status_code == 200:
                # Extract message ID from response
                message_id = None
                try:
                    response_data = response.json()
                    message_id = response_data.get('id')
                    self.logger.debug(f"Received Discord response with message ID: {message_id}")
                except Exception as json_error:
                    self.logger.warning(f"Could not parse Discord response JSON: {json_error}")
                
                self.logger.info(f"Successfully sent new server notification for {server_info.name} ({server_info.ip_address}:{server_info.port})")
                return message_id
            else:
                self.logger.error(f"Failed to send Discord notification. Status: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error sending Discord notification: {str(e)}")
            return None
    
    def delete_server_message(self, message_id: str) -> bool:
        """
        Delete a Discord message using the webhook.
        
        Args:
            message_id: Discord message ID to delete
            
        Returns:
            True if deletion was successful, False otherwise
        """
        if not self.webhook_id or not self.webhook_token:
            self.logger.error("Cannot delete message: webhook credentials not available")
            return False
        
        if not message_id:
            self.logger.warning("Cannot delete message: message_id is empty")
            return False
        
        try:
            # Construct the delete URL
            delete_url = f"https://discord.com/api/webhooks/{self.webhook_id}/{self.webhook_token}/messages/{message_id}"
            
            # Send DELETE request
            response = requests.delete(delete_url)
            
            if response.status_code == 204:  # 204 No Content = successful deletion
                self.logger.info(f"Successfully deleted Discord message: {message_id}")
                return True
            elif response.status_code == 404:
                self.logger.warning(f"Discord message not found (already deleted?): {message_id}")
                return True  # Consider this a success since the message is gone
            else:
                self.logger.error(f"Failed to delete Discord message {message_id}. Status: {response.status_code}")
                if response.text:
                    self.logger.error(f"Discord API response: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error deleting Discord message {message_id}: {str(e)}")
            return False

    def send_server_offline_notification(self, server_info: StandardizedServerInfo, message_id: Optional[str] = None) -> bool:
        """
        Send a Discord notification when a server goes offline.
        If message_id is provided, the original message will be deleted instead of sending a new notification.
        
        Args:
            server_info: Standardized server information
            message_id: Optional message ID to delete instead of sending new message
            
        Returns:
            True if successful, False if failed
        """
        try:
            # If we have a message ID, delete the original message instead of sending offline notification
            if message_id:
                success = self.delete_server_message(message_id)
                if success:
                    self.logger.info(f"Deleted Discord message for offline server: {server_info.name} ({server_info.ip_address}:{server_info.port})")
                else:
                    self.logger.warning(f"Failed to delete Discord message for offline server: {server_info.name}")
                return success
            
            # Fallback: send offline notification if no message ID available
            webhook = DiscordWebhook(url=self.webhook_url)
            
            # Create embed for offline server
            embed = self._create_server_embed(server_info, is_new=False, is_offline=True)
            webhook.add_embed(embed)
            
            # Send the webhook
            response = webhook.execute()
            
            if response.status_code == 200:
                self.logger.info(f"Successfully sent offline notification for {server_info.name} ({server_info.ip_address}:{server_info.port})")
                return True
            else:
                self.logger.error(f"Failed to send offline notification. Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending offline notification: {str(e)}")
            return False
    
    def _create_server_embed(self, server_info: StandardizedServerInfo, is_new: bool = True, is_offline: bool = False) -> DiscordEmbed:
        """
        Create a Discord embed for server information.
        
        Args:
            server_info: Standardized server information
            is_new: Whether this is a new server discovery
            is_offline: Whether the server is going offline
            
        Returns:
            DiscordEmbed object
        """
        # Determine embed color and emoji based on game type
        game_type = server_info.game_type.lower()
        color = self.game_colors.get(game_type, self.game_colors['default'])
        emoji = self.game_emojis.get(game_type, self.game_emojis['default'])
        
        # Create embed title and description
        if is_offline:
            title = f"🔴 Server Offline: {server_info.name}"
            description = f"{emoji} **{server_info.game}** Server ist nicht mehr erreichbar"
            color = 0xFF0000  # Red for offline
        elif is_new:
            title = f"🟢 Neuer Server: {server_info.name}"
            description = f"{emoji} **{server_info.game}** Server wurde entdeckt!"
        else:
            title = f"📊 Server Update: {server_info.name}"
            description = f"{emoji} **{server_info.game}** Server-Informationen aktualisiert"
        
        # Create the embed
        embed = DiscordEmbed(
            title=title,
            description=description,
            color=color,
            timestamp=datetime.now().isoformat()
        )
        
        # Add server information fields
        embed.add_embed_field(
            name="🎮 Spiel",
            value=server_info.game,
            inline=True
        )
        
        embed.add_embed_field(
            name="🗺️ Aktuelle Map",
            value=server_info.map,
            inline=True
        )
        
        embed.add_embed_field(
            name="👥 Spieler",
            value=f"{server_info.players}/{server_info.max_players}",
            inline=True
        )
        
        embed.add_embed_field(
            name="📍 IP-Adresse",
            value=f"`{server_info.ip_address}:{server_info.port}`",
            inline=True
        )
        
        embed.add_embed_field(
            name="🔧 Version",
            value=server_info.version,
            inline=True
        )
        
        embed.add_embed_field(
            name="🔒 Passwort",
            value="🔐 Ja" if server_info.password_protected else "🔓 Nein",
            inline=True
        )
        
        # Add response time if available
        if server_info.response_time > 0:
            embed.add_embed_field(
                name="⚡ Antwortzeit",
                value=f"{server_info.response_time:.2f}s",
                inline=True
            )
        
        # Add protocol-specific Discord fields if available
        if server_info.discord_fields:
            for field in server_info.discord_fields:
                try:
                    embed.add_embed_field(
                        name=field.get('name', 'Unknown Field'),
                        value=field.get('value', 'N/A'),
                        inline=field.get('inline', True)
                    )
                except Exception as e:
                    self.logger.warning(f"Error adding Discord field: {e}")
        
        # Add footer with additional information
        footer_text = f"Protokoll: {server_info.game_type.upper()}"
        if not is_offline:
            footer_text += f" • Entdeckt um {datetime.now().strftime('%H:%M:%S')}"
        
        embed.set_footer(text=footer_text)
        
        # Add thumbnail based on game type (you can add game-specific thumbnails later)
        # embed.set_thumbnail(url="https://example.com/game-icon.png")
        
        return embed
    
    def test_webhook(self) -> bool:
        """
        Test the webhook connection by sending a simple test message.
        
        Returns:
            True if webhook is working, False otherwise
        """
        try:
            webhook = DiscordWebhook(url=self.webhook_url)
            
            embed = DiscordEmbed(
                title="🧪 Webhook Test",
                description="Discord Gameserver Notifier ist erfolgreich verbunden!",
                color=0x00FF00,
                timestamp=datetime.now().isoformat()
            )
            
            embed.add_embed_field(
                name="Status",
                value="✅ Verbindung erfolgreich",
                inline=False
            )
            
            embed.set_footer(text="Test-Nachricht vom Gameserver Notifier")
            
            webhook.add_embed(embed)
            response = webhook.execute()
            
            if response.status_code == 200:
                self.logger.info("Webhook test successful")
                return True
            else:
                self.logger.error(f"Webhook test failed. Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Webhook test error: {str(e)}")
            return False
    
    def get_webhook_info(self) -> Dict[str, Any]:
        """
        Get information about the configured webhook.
        
        Returns:
            Dictionary with webhook configuration info
        """
        return {
            'webhook_url_configured': bool(self.webhook_url),
            'channel_id': self.channel_id,
            'mentions_count': len(self.mentions),
            'mentions': self.mentions,
            'game_mentions_count': len(self.game_mentions),
            'game_mentions': self.game_mentions
        } 