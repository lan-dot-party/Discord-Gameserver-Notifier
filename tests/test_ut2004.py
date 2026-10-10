"""
Tests for the UT2004 (Unreal Tournament 2004) discovery protocol.
"""

import asyncio
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from discord_gameserver_notifier.discovery.protocols.common import ServerResponse
from discord_gameserver_notifier.discovery.protocols.ut2004 import UT2004Protocol
from discord_gameserver_notifier.discovery.server_info_wrapper import ServerInfoWrapper

# Details reply of a UT2004 dedicated server (version 3369), captured on the LAN
DETAILS_REPLY = bytes.fromhex(
    "80000000000000000000611e0000000000000e55543230303420536572766572000a444d2d52616e6b"
    "696e000c7844656174684d6174636800000000001000000000000000000000000230000000"
)

# Rules reply of the same server without a game password
RULES_REPLY = bytes.fromhex(
    "80000000010b5365727665724d6f6465000a646564696361746564000a41646d696e4e616d650006"
    "61646d696e000b41646d696e456d61696c00000e53657276657256657273696f6e00053333363900"
    "0a47616d655374617473000646616c7365000e4d6178537065637461746f7273000232000b4d696e"
    "506c6179657273000230000d456e6454696d6544656c61790005342e3030000a476f616c53636f72"
    "6500033235000a54696d654c696d697400033230000d5472616e736c6f6361746f72000646616c73"
    "65000b576561706f6e53746179000554727565000d466f7263655265737061776e000646616c7365"
    "00"
)

# Rules reply of the same server with a game password: only adds GamePassword=True
RULES_REPLY_PASSWORD = bytes.fromhex(
    "80000000010b5365727665724d6f6465000a646564696361746564000a41646d696e4e616d650006"
    "61646d696e000b41646d696e456d61696c00000e53657276657256657273696f6e00053333363900"
    "0d47616d6550617373776f7264000554727565000a47616d655374617473000646616c7365000e4d"
    "6178537065637461746f7273000232000b4d696e506c6179657273000230000d456e6454696d6544"
    "656c61790005342e3030000a476f616c53636f726500033235000a54696d654c696d697400033230"
    "000d5472616e736c6f6361746f72000646616c7365000b576561706f6e53746179000554727565000d"
    "466f7263655265737061776e000646616c736500"
)


def details_with_players(num_players):
    """Details reply with another player count."""
    offset = DETAILS_REPLY.index(b"xDeathMatch\x00") + len(b"xDeathMatch\x00")
    return DETAILS_REPLY[:offset] + struct.pack("<i", num_players) + DETAILS_REPLY[offset + 4:]


def players_reply(*names):
    """Players reply with one entry per name."""
    data = b"\x80\x00\x00\x00\x02"
    for player_id, name in enumerate(names):
        encoded = name.encode() + b"\x00"
        data += struct.pack("<i", player_id) + bytes([len(encoded)]) + encoded
        data += struct.pack("<iii", 30, 10, 0)
    return data


def make_details(**overrides):
    """Create a Status-like object as returned by opengsq."""
    values = dict(
        server_name="UT2004 Server",
        map_name="DM-Rankin",
        game_type="xDeathMatch",
        num_players=0,
        max_players=16,
        game_port=7777,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


RULES = {
    'ServerMode': 'dedicated',
    'AdminName': 'admin',
    'ServerVersion': '3369',
    'MaxSpectators': '2',
    'GoalScore': '25',
    'TimeLimit': '20',
    'Mutators': [],
}


class TestBuildInfoDict:
    def test_maps_details_and_rules(self):
        info = UT2004Protocol._build_info_dict(make_details(), RULES, [], 7778)

        assert info['hostname'] == "UT2004 Server"
        assert info['map'] == "DM-Rankin"
        assert info['game_mode'] == "Deathmatch"
        assert info['game_class'] == "xDeathMatch"
        assert (info['players'], info['max_players']) == (0, 16)
        assert info['version'] == "3369"
        assert (info['goal_score'], info['time_limit'], info['max_spectators']) == (25, 20, 2)
        assert info['password_protected'] is False
        assert (info['game_port'], info['query_port']) == (7777, 7778)

    def test_game_password_marks_server_protected(self):
        info = UT2004Protocol._build_info_dict(make_details(), {**RULES, 'GamePassword': 'True'}, [], 7778)

        assert info['password_protected'] is True

    def test_missing_rules(self):
        info = UT2004Protocol._build_info_dict(make_details(game_type="MyCustomGame"), {}, [], 7778)

        assert info['game_mode'] == "MyCustomGame"
        assert info['password_protected'] is False
        assert (info['goal_score'], info['time_limit']) == (0, 0)
        assert info['mutators'] == []


def test_discord_fields():
    info = UT2004Protocol._build_info_dict(
        make_details(), {**RULES, 'GamePassword': 'True', 'Mutators': ['InstaGib']}, [], 7778
    )
    fields = {field['name']: field['value'] for field in UT2004Protocol().get_discord_fields(info)}

    assert fields['🎮 Spielmodus'] == "Deathmatch (25 Punkte, 20 min)"
    assert fields['🧩 Mutatoren'] == "InstaGib"
    # Already shown by the standard embed fields
    assert '🔐 Server-Typ' not in fields
    assert '📦 Version' not in fields


def test_wrapper_standardizes_ut2004_server():
    info = UT2004Protocol._build_info_dict(make_details(num_players=3), RULES, [], 7778)
    response = ServerResponse("10.10.100.212", 7777, "ut2004", info, 0.01)

    result = ServerInfoWrapper(protocols={'ut2004': UT2004Protocol()}).standardize_server_response(response)

    assert result.name == "UT2004 Server"
    assert result.game == "Unreal Tournament 2004"
    assert result.map == "DM-Rankin"
    assert (result.players, result.max_players) == (3, 16)
    assert result.version == "3369"
    assert result.port == 7777
    assert result.additional_info['query_port'] == 7778
    assert result.discord_fields


class FakeQueryServer(asyncio.DatagramProtocol):
    """Query port of a UT2004 server: answers details, rules and players queries."""

    def __init__(self, details, rules, players):
        self.details = details
        self.rules = rules
        self.players = players
        self.received = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.received.append(data)
        query_type = data[4]

        if query_type == 0x00:
            self.transport.sendto(self.details, addr)
        elif query_type == 0x01:
            self.transport.sendto(self.rules, addr)
        elif query_type == 0x02 and self.players is not None:
            # An empty server does not answer the players query
            self.transport.sendto(self.players, addr)


class FakeLanListener(asyncio.DatagramProtocol):
    """LAN port of a UT2004 server: answers the LAN query from the query port."""

    def __init__(self, query_server, replies=1):
        self.query_server = query_server
        self.replies = replies

    def datagram_received(self, data, addr):
        if data == UT2004Protocol.DISCOVERY_QUERY:
            for _ in range(self.replies):
                self.query_server.transport.sendto(self.query_server.details, addr)


async def start_fake_server(details=DETAILS_REPLY, rules=RULES_REPLY, players=None, replies=1):
    """Start the query and the LAN listener sockets of a fake server."""
    loop = asyncio.get_running_loop()
    query_transport, query_server = await loop.create_datagram_endpoint(
        lambda: FakeQueryServer(details, rules, players), local_addr=("127.0.0.1", 0)
    )
    lan_transport, _ = await loop.create_datagram_endpoint(
        lambda: FakeLanListener(query_server, replies), local_addr=("127.0.0.1", 0)
    )
    return query_server, (query_transport, lan_transport)


def make_scanning_protocol(lan_port):
    protocol = UT2004Protocol(timeout=1.0)
    protocol.protocol_config.update(lan_port=lan_port, broadcast_timeout=0.3, global_broadcast=False)
    return protocol


async def scan(query_server, transports):
    query_transport, lan_transport = transports
    protocol = make_scanning_protocol(lan_transport.get_extra_info("sockname")[1])

    try:
        return await protocol.scan_servers(["127.0.0.1/32"])
    finally:
        query_transport.close()
        lan_transport.close()


@pytest.mark.asyncio
async def test_scan_finds_empty_ut2004_server():
    query_server, transports = await start_fake_server()
    query_port = transports[0].get_extra_info("sockname")[1]

    servers = await scan(query_server, transports)

    assert len(servers) == 1
    assert servers[0].game_type == "ut2004"
    # Reported with the game port players connect to
    assert (servers[0].ip_address, servers[0].port) == ("127.0.0.1", 7777)
    assert servers[0].server_info['query_port'] == query_port
    assert servers[0].server_info['hostname'] == "UT2004 Server"
    assert servers[0].server_info['map'] == "DM-Rankin"
    assert servers[0].server_info['version'] == "3369"
    assert servers[0].server_info['password_protected'] is False
    # No players query to an empty server
    assert 0x02 not in [data[4] for data in query_server.received]


@pytest.mark.asyncio
async def test_scan_detects_game_password():
    query_server, transports = await start_fake_server(rules=RULES_REPLY_PASSWORD)

    servers = await scan(query_server, transports)

    assert servers[0].server_info['password_protected'] is True


@pytest.mark.asyncio
async def test_scan_reads_players():
    query_server, transports = await start_fake_server(
        details=details_with_players(2), players=players_reply("Gamienator", "Xan")
    )

    servers = await scan(query_server, transports)

    assert servers[0].server_info['players'] == 2
    assert servers[0].server_info['player_names'] == ["Gamienator", "Xan"]


@pytest.mark.asyncio
async def test_scan_reports_server_once_for_repeated_replies():
    query_server, transports = await start_fake_server(replies=3)

    servers = await scan(query_server, transports)

    assert len(servers) == 1


@pytest.mark.asyncio
async def test_scan_ignores_other_udp_services():
    loop = asyncio.get_running_loop()

    class Echo(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, addr):
            self.transport.sendto(b"not a ut2004 server", addr)

    transport, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
    protocol = make_scanning_protocol(transport.get_extra_info("sockname")[1])

    try:
        servers = await protocol.scan_servers(["127.0.0.1/32"])
    finally:
        transport.close()

    assert servers == []
