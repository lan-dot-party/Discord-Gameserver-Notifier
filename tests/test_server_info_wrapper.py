"""
Tests for ServerInfoWrapper - Protocol message parsing for all supported games.

These tests verify that the DGN can correctly understand and standardize
server responses from all supported game protocols.
"""

import sys
import pytest
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Any

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# Define ServerResponse locally to match the protocol's definition
@dataclass
class ServerResponse:
    """Data class for server response information (test copy)"""
    ip_address: str
    port: int
    game_type: str
    server_info: Dict[str, Any]
    response_time: float


# Import from the actual modules
from discord_gameserver_notifier.discovery.server_info_wrapper import ServerInfoWrapper, StandardizedServerInfo


class TestServerInfoWrapper:
    """Tests for the ServerInfoWrapper class."""
    
    def test_wrapper_initialization(self, server_info_wrapper):
        """Test that ServerInfoWrapper initializes correctly."""
        assert server_info_wrapper is not None
        assert isinstance(server_info_wrapper.protocols, dict)
    
    def test_standardized_server_info_dataclass(self):
        """Test StandardizedServerInfo dataclass creation."""
        info = StandardizedServerInfo(
            name="Test Server",
            game="Test Game",
            map="test_map",
            players=5,
            max_players=16,
            version="1.0",
            password_protected=False,
            ip_address="192.168.1.1",
            port=27015,
            game_type="source",
            response_time=0.05,
            additional_info={}
        )
        
        assert info.name == "Test Server"
        assert info.players == 5
        assert info.password_protected is False


class TestSourceProtocolParsing:
    """Tests for Source engine server response parsing."""
    
    def test_parse_source_server(self, server_info_wrapper, source_server_response):
        """Test parsing a Source engine server response."""
        result = server_info_wrapper.standardize_server_response(source_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "Test Counter-Strike 2 Server"
        assert result.game == "Counter-Strike 2"
        assert result.map == "de_dust2"
        assert result.players == 12
        assert result.max_players == 32
        assert result.ip_address == "192.168.1.100"
        assert result.port == 27015
        assert result.game_type == "source"
    
    def test_source_password_detection(self, server_info_wrapper):
        """Test password detection for Source servers."""
        # Public server (visibility = 0)
        public_response = ServerResponse(
            ip_address="192.168.1.1",
            port=27015,
            game_type="source",
            server_info={'visibility': 0, 'name': 'Test'},
            response_time=0.01
        )
        result = server_info_wrapper.standardize_server_response(public_response)
        assert result.password_protected is False
        
        # Private server (visibility = 1)
        private_response = ServerResponse(
            ip_address="192.168.1.1",
            port=27015,
            game_type="source",
            server_info={'visibility': 1, 'name': 'Test'},
            response_time=0.01
        )
        result = server_info_wrapper.standardize_server_response(private_response)
        assert result.password_protected is True
    
    def test_source_additional_info(self, server_info_wrapper, source_server_response):
        """Test that additional Source-specific info is captured."""
        result = server_info_wrapper.standardize_server_response(source_server_response)
        
        assert 'server_type' in result.additional_info
        assert 'environment' in result.additional_info
        assert 'vac' in result.additional_info


class TestRenegadeXProtocolParsing:
    """Tests for RenegadeX server response parsing."""
    
    def test_parse_renegadex_server(self, server_info_wrapper, renegadex_server_response):
        """Test parsing a RenegadeX server response."""
        result = server_info_wrapper.standardize_server_response(renegadex_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "LAN Party RenegadeX"
        assert result.game == "Renegade X"
        assert result.map == "CNC-Field"
        assert result.players == 8
        assert result.max_players == 32
        assert result.version == "5.5.2.0"
        assert result.game_type == "renegadex"
    
    def test_renegadex_game_settings(self, server_info_wrapper, renegadex_server_response):
        """Test RenegadeX game settings are captured."""
        result = server_info_wrapper.standardize_server_response(renegadex_server_response)
        
        assert 'vehicle_limit' in result.additional_info
        assert 'mine_limit' in result.additional_info
        assert 'time_limit' in result.additional_info
        assert result.additional_info['vehicle_limit'] == 8


class TestWarcraft3ProtocolParsing:
    """Tests for Warcraft 3 server response parsing."""
    
    def test_parse_warcraft3_server(self, server_info_wrapper, warcraft3_server_response):
        """Test parsing a Warcraft 3 server response."""
        result = server_info_wrapper.standardize_server_response(warcraft3_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "WC3 LAN Game"
        assert result.game == "Warcraft III"
        assert result.map == "(4)EchoIsles.w3m"
        assert result.players == 4
        assert result.max_players == 12
        assert result.game_type == "warcraft3"
    
    def test_warcraft3_product_info(self, server_info_wrapper, warcraft3_server_response):
        """Test Warcraft 3 product info is captured."""
        result = server_info_wrapper.standardize_server_response(warcraft3_server_response)
        
        assert 'product' in result.additional_info
        assert result.additional_info['product'] == 'W3XP'


class TestFlatout2ProtocolParsing:
    """Tests for Flatout 2 server response parsing."""
    
    def test_parse_flatout2_server(self, server_info_wrapper, flatout2_server_response):
        """Test parsing a Flatout 2 server response."""
        result = server_info_wrapper.standardize_server_response(flatout2_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "Flatout 2 Racing Server"
        assert result.game == "Flatout 2"
        assert result.map == "Spring Circuit"
        assert result.players == 6
        assert result.max_players == 8
        assert result.game_type == "flatout2"


class TestUT3ProtocolParsing:
    """Tests for Unreal Tournament 3 server response parsing."""
    
    def test_parse_ut3_server(self, server_info_wrapper, ut3_server_response):
        """Test parsing a UT3 server response."""
        result = server_info_wrapper.standardize_server_response(ut3_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "UT3 Deathmatch Server"
        assert result.game == "Unreal Tournament 3"
        assert result.map == "DM-Deck"
        assert result.players == 10
        assert result.max_players == 16
        assert result.game_type == "ut3"
    
    def test_ut3_gamemode_info(self, server_info_wrapper, ut3_server_response):
        """Test UT3 gamemode info is captured."""
        result = server_info_wrapper.standardize_server_response(ut3_server_response)
        
        assert 'gamemode' in result.additional_info
        assert result.additional_info['gamemode'] == 'Deathmatch'


class TestToxikkProtocolParsing:
    """Tests for Toxikk server response parsing."""
    
    def test_parse_toxikk_server(self, server_info_wrapper, toxikk_server_response):
        """Test parsing a Toxikk server response."""
        result = server_info_wrapper.standardize_server_response(toxikk_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "Toxikk LAN Server"
        assert result.game == "Toxikk"
        assert result.map == "SC-Dekk"
        assert result.players == 8
        assert result.max_players == 16
        assert result.game_type == "toxikk"


class TestCoD4ProtocolParsing:
    """Tests for Call of Duty 4 server response parsing."""
    
    def test_parse_cod4_server(self, server_info_wrapper, cod4_server_response):
        """Test parsing a CoD4 server response."""
        result = server_info_wrapper.standardize_server_response(cod4_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "CoD4 LAN Party Server"
        assert result.game == "Call of Duty 4"
        assert result.map == "mp_crash"
        assert result.players == 12
        assert result.max_players == 18
        assert result.game_type == "cod4"
    
    def test_cod4_hardcore_mode(self, server_info_wrapper, cod4_server_response):
        """Test CoD4 hardcore mode detection."""
        result = server_info_wrapper.standardize_server_response(cod4_server_response)
        
        assert 'hardcore' in result.additional_info
        assert result.additional_info['hardcore'] is True


class TestHalo1ProtocolParsing:
    """Tests for Halo 1 server response parsing."""
    
    def test_parse_halo1_server(self, server_info_wrapper, halo1_server_response):
        """Test parsing a Halo 1 server response."""
        result = server_info_wrapper.standardize_server_response(halo1_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "Halo CE LAN Server"
        assert result.game == "Halo 1 (Combat Evolved)"
        assert result.map == "bloodgulch"
        assert result.players == 8
        assert result.max_players == 16
        assert result.game_type == "halo1"


class TestQuake3ProtocolParsing:
    """Tests for Quake 3 Arena server response parsing."""
    
    def test_parse_quake3_server(self, server_info_wrapper, quake3_server_response):
        """Test parsing a Quake 3 server response."""
        result = server_info_wrapper.standardize_server_response(quake3_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "Quake 3 Arena Server"
        assert result.game == "Quake 3 Arena"
        assert result.map == "q3dm17"
        assert result.players == 6
        assert result.max_players == 16
        assert result.game_type == "quake3"


class TestCnCGeneralsProtocolParsing:
    """Tests for Command & Conquer Generals server response parsing."""
    
    def test_parse_cnc_generals_server(self, server_info_wrapper, cnc_generals_server_response):
        """Test parsing a CnC Generals server response."""
        result = server_info_wrapper.standardize_server_response(cnc_generals_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert "Generals" in result.name or "CnC" in result.name
        assert result.game == "Command & Conquer Generals Zero Hour"
        assert result.players == 4
        assert result.game_type == "cnc_generals"


class TestAVP2ProtocolParsing:
    """Tests for Alien vs Predator 2 server response parsing."""
    
    def test_parse_avp2_server(self, server_info_wrapper, avp2_server_response):
        """Test parsing an AVP2 server response."""
        result = server_info_wrapper.standardize_server_response(avp2_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "AVP2 LAN Server"
        assert result.game == "Alien vs Predator 2"
        assert result.map == "DM_Leadworks"
        assert result.players == 8
        assert result.max_players == 16
        assert result.game_type == "avp2"
    
    def test_avp2_race_limits(self, server_info_wrapper, avp2_server_response):
        """Test AVP2 race limits are captured."""
        result = server_info_wrapper.standardize_server_response(avp2_server_response)
        
        assert 'race_limits' in result.additional_info


class TestBattlefield2ProtocolParsing:
    """Tests for Battlefield 2 server response parsing."""
    
    def test_parse_battlefield2_server(self, server_info_wrapper, battlefield2_server_response):
        """Test parsing a Battlefield 2 server response."""
        result = server_info_wrapper.standardize_server_response(battlefield2_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "BF2 LAN Server"
        assert result.game == "Battlefield 2"
        assert result.map == "Strike at Karkand"
        assert result.players == 24
        assert result.max_players == 64
        assert result.game_type == "battlefield2"
    
    def test_battlefield2_team_scores(self, server_info_wrapper, battlefield2_server_response):
        """Test BF2 team scores are captured."""
        result = server_info_wrapper.standardize_server_response(battlefield2_server_response)
        
        assert 'score_1' in result.additional_info
        assert 'score_2' in result.additional_info


class TestSeriousSamTFEProtocolParsing:
    """Tests for Serious Sam Classic: The First Encounter server response parsing."""
    
    def test_parse_ssc_tfe_server(self, server_info_wrapper, ssc_tfe_server_response):
        """Test parsing a Serious Sam TFE server response."""
        result = server_info_wrapper.standardize_server_response(ssc_tfe_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "Serious Sam TFE Coop"
        assert "First Encounter" in result.game
        assert result.map == "Hatshepsut"
        assert result.players == 4
        assert result.max_players == 8
        assert result.game_type == "ssc_tfe"


class TestSeriousSamTSEProtocolParsing:
    """Tests for Serious Sam Classic: The Second Encounter server response parsing."""
    
    def test_parse_ssc_tse_server(self, server_info_wrapper, ssc_tse_server_response):
        """Test parsing a Serious Sam TSE server response."""
        result = server_info_wrapper.standardize_server_response(ssc_tse_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "Serious Sam TSE Coop"
        assert "Second Encounter" in result.game
        assert result.map == "Sierra de Chiapas"
        assert result.players == 6
        assert result.max_players == 8
        assert result.game_type == "ssc_tse"


class TestElDewritoProtocolParsing:
    """Tests for ElDewrito server response parsing."""
    
    def test_parse_eldewrito_server(self, server_info_wrapper, eldewrito_server_response):
        """Test parsing an ElDewrito server response."""
        result = server_info_wrapper.standardize_server_response(eldewrito_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "ElDewrito LAN Server"
        assert "ElDewrito" in result.game or "Halo" in result.game
        assert result.map == "Valhalla"
        assert result.players == 10
        assert result.max_players == 16
        assert result.game_type == "eldewrito"


class TestAoE1ProtocolParsing:
    """Tests for Age of Empires 1 server response parsing."""
    
    def test_parse_aoe1_server(self, server_info_wrapper, aoe1_server_response):
        """Test parsing an Age of Empires 1 server response."""
        result = server_info_wrapper.standardize_server_response(aoe1_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "AoE1 LAN Game"
        assert result.game == "Age of Empires 1"
        assert result.map == "Coastal"
        assert result.players == 4
        assert result.max_players == 8
        assert result.game_type == "aoe1"


class TestAoE2ProtocolParsing:
    """Tests for Age of Empires 2 server response parsing."""
    
    def test_parse_aoe2_server(self, server_info_wrapper, aoe2_server_response):
        """Test parsing an Age of Empires 2 server response."""
        result = server_info_wrapper.standardize_server_response(aoe2_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "AoE2 HD LAN Game"
        assert result.game == "Age of Empires 2"
        assert result.map == "Arabia"
        assert result.players == 4
        assert result.max_players == 8
        assert result.game_type == "aoe2"


class TestCoD1ProtocolParsing:
    """Tests for Call of Duty 1 server response parsing."""
    
    def test_parse_cod1_server(self, server_info_wrapper, cod1_server_response):
        """Test parsing a CoD1 server response."""
        result = server_info_wrapper.standardize_server_response(cod1_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "CoD1 LAN Server"
        assert result.game == "Call of Duty"
        assert result.map == "mp_carentan"
        assert result.players == 8
        assert result.max_players == 16
        assert result.game_type == "cod1"


class TestStrongholdCrusaderProtocolParsing:
    """Tests for Stronghold Crusader server response parsing."""
    
    def test_parse_stronghold_crusader_server(self, server_info_wrapper, stronghold_crusader_server_response):
        """Test parsing a Stronghold Crusader server response."""
        result = server_info_wrapper.standardize_server_response(stronghold_crusader_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert "Stronghold" in result.name or "Crusader" in result.game
        assert result.game == "Stronghold Crusader"
        assert result.players == 3
        assert result.max_players == 8
        assert result.game_type == "stronghold_crusader"


class TestStrongholdCEProtocolParsing:
    """Tests for Stronghold Crusader Extreme server response parsing."""
    
    def test_parse_stronghold_ce_server(self, server_info_wrapper, stronghold_ce_server_response):
        """Test parsing a Stronghold Crusader Extreme server response."""
        result = server_info_wrapper.standardize_server_response(stronghold_ce_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert "Stronghold" in result.name or "Extreme" in result.game
        assert "Extreme" in result.game
        assert result.players == 4
        assert result.max_players == 8
        assert result.game_type == "stronghold_ce"


class TestFear2ProtocolParsing:
    """Tests for F.E.A.R. 2 server response parsing."""
    
    def test_parse_fear2_server(self, server_info_wrapper, fear2_server_response):
        """Test parsing a F.E.A.R. 2 server response."""
        result = server_info_wrapper.standardize_server_response(fear2_server_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "FEAR2 LAN Server"
        assert "F.E.A.R. 2" in result.game
        assert result.map == "Alma_Museum"
        assert result.players == 6
        assert result.max_players == 16
        assert result.game_type == "fear2"


class TestGenericFallbackParsing:
    """Tests for generic/unknown protocol fallback parsing."""
    
    def test_parse_unknown_game_type(self, server_info_wrapper):
        """Test parsing an unknown game type uses generic fallback."""
        unknown_response = ServerResponse(
            ip_address="192.168.1.200",
            port=9999,
            game_type="unknown_game",
            server_info={
                'name': 'Unknown Game Server',
                'map': 'some_map',
                'players': 4,
                'max_players': 8
            },
            response_time=0.05
        )
        
        result = server_info_wrapper.standardize_server_response(unknown_response)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == "Unknown Game Server"
        assert result.map == "some_map"
        assert result.game_type == "unknown_game"
    
    def test_fallback_with_hostname_field(self, server_info_wrapper):
        """Test fallback correctly uses 'hostname' field if 'name' is missing."""
        response = ServerResponse(
            ip_address="192.168.1.200",
            port=9999,
            game_type="unknown_game",
            server_info={
                'hostname': 'Server via Hostname',
                'map': 'test_map'
            },
            response_time=0.05
        )
        
        result = server_info_wrapper.standardize_server_response(response)
        
        assert result.name == "Server via Hostname"


class TestAllProtocolsIntegration:
    """Integration tests that verify all protocols parse correctly."""
    
    def test_all_server_responses_parse_without_error(self, server_info_wrapper, all_server_responses):
        """Test that all server response fixtures parse without raising exceptions."""
        for game_type, response in all_server_responses.items():
            try:
                result = server_info_wrapper.standardize_server_response(response)
                
                # Basic validation
                assert isinstance(result, StandardizedServerInfo)
                assert result.name is not None and len(result.name) > 0
                assert result.ip_address is not None
                assert result.port > 0
                assert result.game_type == game_type
                
            except Exception as e:
                pytest.fail(f"Failed to parse {game_type} server response: {e}")
    
    def test_all_server_responses_have_required_fields(self, server_info_wrapper, all_server_responses):
        """Test that all parsed responses have all required fields populated."""
        required_fields = ['name', 'game', 'map', 'players', 'max_players', 'ip_address', 'port', 'game_type']
        
        for game_type, response in all_server_responses.items():
            result = server_info_wrapper.standardize_server_response(response)
            
            for field in required_fields:
                value = getattr(result, field)
                assert value is not None, f"Field '{field}' is None for {game_type}"
    
    def test_format_server_summary(self, server_info_wrapper, all_server_responses):
        """Test that server summaries can be formatted for all game types."""
        for game_type, response in all_server_responses.items():
            result = server_info_wrapper.standardize_server_response(response)
            
            summary = server_info_wrapper.format_server_summary(result)
            
            assert isinstance(summary, str)
            assert len(summary) > 0
            # Summary should contain key information
            assert result.name in summary or result.game in summary


class TestServerInfoWrapperSerialization:
    """Tests for serialization/deserialization of server info."""
    
    def test_to_dict(self, server_info_wrapper, source_server_response):
        """Test converting StandardizedServerInfo to dictionary."""
        result = server_info_wrapper.standardize_server_response(source_server_response)
        
        data = server_info_wrapper.to_dict(result)
        
        assert isinstance(data, dict)
        assert data['name'] == result.name
        assert data['ip_address'] == result.ip_address
        assert data['players'] == result.players
    
    def test_from_dict(self, server_info_wrapper):
        """Test creating StandardizedServerInfo from dictionary."""
        data = {
            'name': 'Test Server',
            'game': 'Test Game',
            'map': 'test_map',
            'players': 5,
            'max_players': 10,
            'version': '1.0',
            'password_protected': False,
            'ip_address': '192.168.1.1',
            'port': 27015,
            'game_type': 'source',
            'response_time': 0.02,
            'additional_info': {}
        }
        
        result = server_info_wrapper.from_dict(data)
        
        assert isinstance(result, StandardizedServerInfo)
        assert result.name == 'Test Server'
        assert result.players == 5
    
    def test_round_trip_serialization(self, server_info_wrapper, source_server_response):
        """Test that to_dict -> from_dict preserves data."""
        original = server_info_wrapper.standardize_server_response(source_server_response)
        
        data = server_info_wrapper.to_dict(original)
        restored = server_info_wrapper.from_dict(data)
        
        assert original.name == restored.name
        assert original.game == restored.game
        assert original.map == restored.map
        assert original.players == restored.players
        assert original.ip_address == restored.ip_address
        assert original.port == restored.port

