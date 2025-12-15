"""
Pytest configuration and shared fixtures for DGN tests.
"""

import os
import sys
import pytest
import tempfile
import yaml
from pathlib import Path
from unittest.mock import MagicMock, patch
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


@pytest.fixture
def temp_config_dir(tmp_path):
    """Create a temporary directory with a valid config file."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    return config_dir


@pytest.fixture
def minimal_config():
    """Minimal valid configuration for testing."""
    return {
        'network': {
            'scan_ranges': ['192.168.1.0/24'],
            'scan_interval': 300,
            'timeout': 5
        },
        'games': {
            'enabled': ['source']
        },
        'discord': {
            'webhook_url': 'https://discord.com/api/webhooks/123456789/abcdefghijklmnopqrstuvwxyz',
            'channel_id': '123456789',
            'mentions': [],
            'game_mentions': {}
        },
        'database': {
            'path': ':memory:',  # Use in-memory SQLite for tests
            'cleanup_after_fails': 5
        },
        'api': {
            'enabled': False,
            'host': '0.0.0.0',
            'port': 8080
        },
        'debugging': {
            'log_level': 'DEBUG',
            'log_to_file': False,
            'log_file': './test.log'
        }
    }


@pytest.fixture
def temp_config_file(temp_config_dir, minimal_config):
    """Create a temporary config file with minimal valid configuration."""
    config_file = temp_config_dir / "config.yaml"
    with open(config_file, 'w') as f:
        yaml.dump(minimal_config, f)
    return config_file


@pytest.fixture
def server_info_wrapper():
    """Create a ServerInfoWrapper instance for testing."""
    return ServerInfoWrapper()


# ============================================================================
# Sample Server Responses for all supported game types
# ============================================================================

@pytest.fixture
def source_server_response():
    """Sample Source engine server response."""
    return ServerResponse(
        ip_address="192.168.1.100",
        port=27015,
        game_type="source",
        server_info={
            'name': 'Test Counter-Strike 2 Server',
            'map': 'de_dust2',
            'game': 'Counter-Strike 2',
            'players': 12,
            'max_players': 32,
            'bots': 0,
            'server_type': 100,  # 'd' = dedicated
            'environment': 108,  # 'l' = Linux
            'protocol': 17,
            'visibility': 0,  # public
            'vac': 1,  # enabled
            'version': '1.39.1.5',
            'port': 27015,
            'steam_id': '90123456789012345',
            'keywords': 'secure,cs2',
            'folder': 'cs2',
            'id': 730
        },
        response_time=0.025
    )


@pytest.fixture
def renegadex_server_response():
    """Sample RenegadeX server response."""
    return ServerResponse(
        ip_address="192.168.1.101",
        port=7777,
        game_type="renegadex",
        server_info={
            'name': 'LAN Party RenegadeX',
            'map': 'CNC-Field',
            'game_version': '5.5.2.0',
            'players': 8,
            'max_players': 32,
            'passworded': False,
            'steam_required': False,
            'team_mode': 1,
            'game_type': 1,
            'ranked': False,
            'vehicle_limit': 8,
            'mine_limit': 6,
            'time_limit': 30,
            'spawn_crates': True
        },
        response_time=0.015
    )


@pytest.fixture
def warcraft3_server_response():
    """Sample Warcraft 3 server response."""
    return ServerResponse(
        ip_address="192.168.1.102",
        port=6112,
        game_type="warcraft3",
        server_info={
            'name': 'WC3 LAN Game',
            'map': '(4)EchoIsles.w3m',
            'product': 'W3XP',
            'version': 30,
            'players': 4,
            'max_players': 12,
            'host_counter': 1,
            'entry_key': 0
        },
        response_time=0.010
    )


@pytest.fixture
def flatout2_server_response():
    """Sample Flatout 2 server response."""
    return ServerResponse(
        ip_address="192.168.1.103",
        port=33220,
        game_type="flatout2",
        server_info={
            'hostname': 'Flatout 2 Racing Server',
            'game': 'Flatout 2',
            'map': 'Spring Circuit',
            'players': 6,
            'max_players': 8,
            'timestamp': '12345678',
            'flags': '0',
            'status': '1',
            'config': ''
        },
        response_time=0.020
    )


@pytest.fixture
def ut3_server_response():
    """Sample Unreal Tournament 3 server response."""
    return ServerResponse(
        ip_address="192.168.1.104",
        port=7777,
        game_type="ut3",
        server_info={
            'name': 'UT3 Deathmatch Server',
            'game': 'Unreal Tournament 3',
            'map': 'DM-Deck',
            'players': 10,
            'max_players': 16,
            'version': 'UT3',
            'password_protected': False,
            'gamemode': 'Deathmatch',
            'mutators': ['WeaponReplacement'],
            'frag_limit': 50,
            'time_limit': 15,
            'numbots': 4,
            'bot_skill': 'Average',
            'pure_server': True,
            'vs_bots': 'None',
            'force_respawn': False,
            'stats_enabled': True,
            'lan_mode': True
        },
        response_time=0.018
    )


@pytest.fixture
def toxikk_server_response():
    """Sample Toxikk server response."""
    return ServerResponse(
        ip_address="192.168.1.105",
        port=7777,
        game_type="toxikk",
        server_info={
            'name': 'Toxikk LAN Server',
            'game': 'Toxikk',
            'map': 'SC-Dekk',
            'players': 8,
            'max_players': 16,
            'version': 'Toxikk',
            'password_protected': False,
            'gamemode': 'Squad Assault',
            'gametype': 'SA',
            'mutators': [],
            'frag_limit': 50,
            'time_limit': 20,
            'numbots': 2,
            'bot_skill': 'Experienced',
            'pure_server': True,
            'vs_bots': 'None',
            'force_respawn': True,
            'stats_enabled': False,
            'lan_mode': True,
            'password': 0
        },
        response_time=0.016
    )


@pytest.fixture
def cod4_server_response():
    """Sample Call of Duty 4 server response."""
    return ServerResponse(
        ip_address="192.168.1.106",
        port=28960,
        game_type="cod4",
        server_info={
            'hostname': 'CoD4 LAN Party Server',
            'map_name': 'mp_crash',
            'current_players': 12,
            'max_players': 18,
            'additional_info': {
                'shortversion': '1.7',
                'gametype': 'tdm',
                'pswrd': '0',
                'hc': '1',
                'ff': '0',
                'mod': '0',
                'voice': '1',
                'pure': '1',
                'build': 'COD4',
                'protocol': '6',
                'sv_maxPing': '200'
            }
        },
        response_time=0.012
    )


@pytest.fixture
def halo1_server_response():
    """Sample Halo 1 server response."""
    return ServerResponse(
        ip_address="192.168.1.107",
        port=2302,
        game_type="halo1",
        server_info={
            'hostname': 'Halo CE LAN Server',
            'mapname': 'bloodgulch',
            'numplayers': '8',
            'maxplayers': '16',
            'gamever': '01.00.10.0621',
            'gametype': 'CTF',
            'gamevariant': 'CTF',
            'gamemode': 'openplaying',
            'password': '0',
            'dedicated': '1',
            'teamplay': '1',
            'fraglimit': '3',
            'game_classic': '0',
            'player_flags': '',
            'game_flags': '',
            'players_list': [],
            'teams_list': []
        },
        response_time=0.020
    )


@pytest.fixture
def quake3_server_response():
    """Sample Quake 3 Arena server response."""
    return ServerResponse(
        ip_address="192.168.1.108",
        port=27960,
        game_type="quake3",
        server_info={
            'hostname': 'Quake 3 Arena Server',
            'map_name': 'q3dm17',
            'current_players': 6,
            'max_players': 16,
            'additional_info': {
                'gametype': '0',
                'protocol': '68',
                'gamename': 'Quake3Arena',
                'g_needpass': '0',
                'pure': '1',
                'voip': 'opus',
                'g_humanplayers': '6',
                'sv_maxclients': '16'
            }
        },
        response_time=0.014
    )


@pytest.fixture
def cnc_generals_server_response():
    """Sample Command & Conquer Generals server response."""
    return ServerResponse(
        ip_address="192.168.1.109",
        port=8086,
        game_type="cnc_generals",
        server_info={
            'name': 'CnC Generals Zero Hour',
            'game': 'Command & Conquer Generals Zero Hour',
            'map': 'Unknown',
            'players': 4,
            'max_players': 0,
            'packets_received': 3
        },
        response_time=0.030
    )


@pytest.fixture
def avp2_server_response():
    """Sample Alien vs Predator 2 server response."""
    return ServerResponse(
        ip_address="192.168.1.110",
        port=27888,
        game_type="avp2",
        server_info={
            'hostname': 'AVP2 LAN Server',
            'game': 'Alien vs Predator 2',
            'mapname': 'DM_Leadworks',
            'numplayers': '8',
            'maxplayers': '16',
            'gamever': '1.09',
            'mspatch': '1',
            'lock': '0',
            'gametype': 'Deathmatch',
            'gamemode': 'Standard',
            'ded': '1',
            'website': '',
            'bandwidth': 'T1',
            'maxa': '8',
            'maxm': '8',
            'maxp': '8',
            'maxc': '0',
            'ff': '0',
            'speed': '100',
            'damage': '100',
            'respawn': '5',
            'hitloc': '1'
        },
        response_time=0.022
    )


@pytest.fixture
def battlefield2_server_response():
    """Sample Battlefield 2 server response."""
    return ServerResponse(
        ip_address="192.168.1.111",
        port=29900,
        game_type="battlefield2",
        server_info={
            'hostname': 'BF2 LAN Server',
            'mapname': 'Strike at Karkand',
            'numplayers': '24',
            'maxplayers': '64',
            'gamever': '1.5',
            'password': '0',
            'gamename': 'battlefield2',
            'dedicated': '1',
            'ranked': '0',
            'punkbuster': '1',
            'team_1': 'US',
            'team_2': 'MEC',
            'score_1': '150',
            'score_2': '120',
            'timelimit': '60',
            'roundtime': '45',
            'bf2_cc': '0',
            'bf2_ranked': '0',
            'bf2_pure': '1',
            'bf2_mapsize': '64',
            'bf2_globalunlocks': '0',
            'bf2_fps': '30',
            'bf2_autobalanced': '1',
            'bf2_friendlyfire': '0',
            'bf2_tkmode': 'punish',
            'bf2_startdelay': '15',
            'bf2_spawntime': '15',
            'bf2_sponsortext': '',
            'bf2_sponsorlogo_url': '',
            'bf2_communitylogo_url': '',
            'players_list': [],
            'teams_list': []
        },
        response_time=0.028
    )


@pytest.fixture
def ssc_tfe_server_response():
    """Sample Serious Sam Classic: The First Encounter server response."""
    return ServerResponse(
        ip_address="192.168.1.112",
        port=25600,
        game_type="ssc_tfe",
        server_info={
            'hostname': 'Serious Sam TFE Coop',
            'mapname': 'Hatshepsut',
            'numplayers': 4,
            'maxplayers': 8,
            'gamever': '1.05',
            'password': '0',
            'gamename': 'serioussam',
            'location': 'Germany',
            'gametype': 'Cooperative',
            'activemod': '',
            'gamemode': 'cooperative',
            'difficulty': 'Normal',
            'friendlyfire': '0',
            'weaponsstay': '0',
            'ammostays': '0',
            'infiniteammo': '0',
            'hostport': '25600'
        },
        response_time=0.019
    )


@pytest.fixture
def ssc_tse_server_response():
    """Sample Serious Sam Classic: The Second Encounter server response."""
    return ServerResponse(
        ip_address="192.168.1.113",
        port=25600,
        game_type="ssc_tse",
        server_info={
            'hostname': 'Serious Sam TSE Coop',
            'mapname': 'Sierra de Chiapas',
            'numplayers': 6,
            'maxplayers': 8,
            'gamever': '1.07',
            'password': '0',
            'gamename': 'serioussamse',
            'location': 'Germany',
            'gametype': 'Cooperative',
            'activemod': '',
            'gamemode': 'cooperative',
            'difficulty': 'Hard',
            'friendlyfire': '1',
            'weaponsstay': '0',
            'ammostays': '0',
            'infiniteammo': '0',
            'hostport': '25600'
        },
        response_time=0.017
    )


@pytest.fixture
def eldewrito_server_response():
    """Sample ElDewrito server response."""
    return ServerResponse(
        ip_address="192.168.1.114",
        port=11775,
        game_type="eldewrito",
        server_info={
            'name': 'ElDewrito LAN Server',
            'map': 'Valhalla',
            'num_players': 10,
            'max_players': 16,
            'eldewrito_version': '0.6.1',
            'game_version': '0.6.1.0',
            'status': 'InGame',
            'host_player': 'LAN_Host',
            'teams': True,
            'is_dedicated': True,
            'variant': 'Slayer',
            'variant_type': 'Slayer',
            'mod_count': 0,
            'mod_package_name': '',
            'sprint_state': '2',
            'dual_wielding': '1',
            'assassination_enabled': '0',
            'xnkid': '',
            'xnaddr': '',
            'players': []
        },
        response_time=0.021
    )


@pytest.fixture
def aoe1_server_response():
    """Sample Age of Empires 1 server response."""
    return ServerResponse(
        ip_address="192.168.1.115",
        port=2300,
        game_type="aoe1",
        server_info={
            'name': 'AoE1 LAN Game',
            'map': 'Coastal',
            'players': 4,
            'max_players': 8,
            'game_version': '1.0c',
            'game_mode': 'Random Map',
            'raw': {}
        },
        response_time=0.025
    )


@pytest.fixture
def aoe2_server_response():
    """Sample Age of Empires 2 server response."""
    return ServerResponse(
        ip_address="192.168.1.116",
        port=2300,
        game_type="aoe2",
        server_info={
            'name': 'AoE2 HD LAN Game',
            'map': 'Arabia',
            'players': 4,
            'max_players': 8,
            'game_version': '2.0a',
            'game_mode': 'Random Map',
            'civilizations': ['Britons', 'Franks', 'Goths', 'Teutons'],
            'raw': {}
        },
        response_time=0.024
    )


@pytest.fixture
def cod1_server_response():
    """Sample Call of Duty 1 server response."""
    return ServerResponse(
        ip_address="192.168.1.117",
        port=28960,
        game_type="cod1",
        server_info={
            'hostname': 'CoD1 LAN Server',
            'map_name': 'mp_carentan',
            'current_players': 8,
            'max_players': 16,
            'additional_info': {
                'shortversion': '1.5',
                'gametype': 'tdm',
                'mod': '0',
                'pure': '1',
                'hw': 'PC',
                'protocol': '1',
                'sv_maxPing': '200'
            }
        },
        response_time=0.015
    )


@pytest.fixture
def stronghold_crusader_server_response():
    """Sample Stronghold Crusader server response."""
    return ServerResponse(
        ip_address="192.168.1.118",
        port=2301,
        game_type="stronghold_crusader",
        server_info={
            'name': 'Stronghold Crusader Game',
            'map': 'Custom Map 1',
            'players': 3,
            'max_players': 8,
            'game_version': '1.41',
            'passworded': False,
            'game_type': 'Stronghold Crusader',
            'raw': {}
        },
        response_time=0.030
    )


@pytest.fixture
def stronghold_ce_server_response():
    """Sample Stronghold Crusader Extreme server response."""
    return ServerResponse(
        ip_address="192.168.1.119",
        port=2300,
        game_type="stronghold_ce",
        server_info={
            'name': 'Stronghold Crusader Extreme',
            'map': 'Extreme Map 1',
            'players': 4,
            'max_players': 8,
            'game_version': '1.4.1',
            'passworded': False,
            'game_type': 'Stronghold Crusader Extreme',
            'raw': {}
        },
        response_time=0.028
    )


@pytest.fixture
def fear2_server_response():
    """Sample F.E.A.R. 2 server response."""
    return ServerResponse(
        ip_address="192.168.1.120",
        port=27888,
        game_type="fear2",
        server_info={
            'hostname': 'FEAR2 LAN Server',
            'game': 'F.E.A.R. 2: Project Origin',
            'mapname': 'Alma_Museum',
            'numplayers': '6',
            'maxplayers': '16',
            'gamever': '1.0',
            'requirespassword': '0',
            'gametype': 'Deathmatch',
            'gamemode': 'Standard',
            'gameid': 'fear2',
            'worldindex': '0',
            'contentpackageindex': '0',
            'ranked': '0',
            'lanonly': '1',
            'sessionstarted': '1',
            'gamename': 'FEAR2'
        },
        response_time=0.023
    )


@pytest.fixture
def all_server_responses(
    source_server_response,
    renegadex_server_response,
    warcraft3_server_response,
    flatout2_server_response,
    ut3_server_response,
    toxikk_server_response,
    cod4_server_response,
    halo1_server_response,
    quake3_server_response,
    cnc_generals_server_response,
    avp2_server_response,
    battlefield2_server_response,
    ssc_tfe_server_response,
    ssc_tse_server_response,
    eldewrito_server_response,
    aoe1_server_response,
    aoe2_server_response,
    cod1_server_response,
    stronghold_crusader_server_response,
    stronghold_ce_server_response,
    fear2_server_response
):
    """Return all server response fixtures as a dictionary."""
    return {
        'source': source_server_response,
        'renegadex': renegadex_server_response,
        'warcraft3': warcraft3_server_response,
        'flatout2': flatout2_server_response,
        'ut3': ut3_server_response,
        'toxikk': toxikk_server_response,
        'cod4': cod4_server_response,
        'halo1': halo1_server_response,
        'quake3': quake3_server_response,
        'cnc_generals': cnc_generals_server_response,
        'avp2': avp2_server_response,
        'battlefield2': battlefield2_server_response,
        'ssc_tfe': ssc_tfe_server_response,
        'ssc_tse': ssc_tse_server_response,
        'eldewrito': eldewrito_server_response,
        'aoe1': aoe1_server_response,
        'aoe2': aoe2_server_response,
        'cod1': cod1_server_response,
        'stronghold_crusader': stronghold_crusader_server_response,
        'stronghold_ce': stronghold_ce_server_response,
        'fear2': fear2_server_response
    }

