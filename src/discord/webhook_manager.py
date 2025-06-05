"""
Discord webhook management and message handling
"""

import logging
import asyncio
from typing import Optional, Dict, Any
from discord_webhook import DiscordWebhook, DiscordEmbed
from datetime import datetime

from ..discovery.server_info_wrapper import StandardizedServerInfo


class WebhookManager:
    """
    Manages Discord webhook communications for game server notifications.
    Handles sending embeds for new server discoveries and server status updates.
    """
    
    def __init__(self, webhook_url: str, channel_id: Optional[str] = None, mentions: Optional[list] = None):
        """
        Initialize the WebhookManager.
        
        Args:
            webhook_url: Discord webhook URL
            channel_id: Optional Discord channel ID for reference
            mentions: Optional list of mentions to include in messages
        """
        self.webhook_url = webhook_url
        self.channel_id = channel_id
        self.mentions = mentions or []
        self.logger = logging.getLogger("GameServerNotifier.WebhookManager")
        
        # Game-specific colors and emojis for embeds
        self.game_colors = {
            'source': 0xFF6600,      # Orange for Source Engine
            'renegadex': 0x00FF00,   # Green for RenegadeX
            'warcraft3': 0x0066CC,   # Blue for Warcraft 3
            'flatout2': 0xFF0000,    # Red for Flatout 2
            'default': 0x7289DA      # Discord Blurple
        }
        
        self.game_emojis = {
            'source': '🎮',
            'renegadex': '⚔️',
            'warcraft3': '🏰',
            'flatout2': '🏎️',
            'default': '🎯'
        }
        
        self.logger.info(f"WebhookManager initialized for channel {channel_id}")
    
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
            
            # Add mentions if configured
            if self.mentions:
                mention_text = " ".join(self.mentions)
                webhook.content = f"{mention_text} 🎉 **Neuer Gameserver im Netzwerk entdeckt!**"
            
            # Create embed for server information
            embed = self._create_server_embed(server_info, is_new=True)
            webhook.add_embed(embed)
            
            # Send the webhook
            response = webhook.execute()
            
            if response.status_code == 200:
                # Extract message ID from response if available
                message_id = None
                if hasattr(response, 'json') and response.json():
                    message_id = response.json().get('id')
                
                self.logger.info(f"Successfully sent new server notification for {server_info.name} ({server_info.ip_address}:{server_info.port})")
                return message_id
            else:
                self.logger.error(f"Failed to send Discord notification. Status: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error sending Discord notification: {str(e)}")
            return None
    
    def send_server_offline_notification(self, server_info: StandardizedServerInfo, message_id: Optional[str] = None) -> bool:
        """
        Send a Discord notification when a server goes offline.
        
        Args:
            server_info: Standardized server information
            message_id: Optional message ID to edit instead of sending new message
            
        Returns:
            True if successful, False if failed
        """
        try:
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
            'mentions': self.mentions
        } 