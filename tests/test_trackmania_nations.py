"""
Tests for the Trackmania Nations discovery protocol.
"""

import asyncio
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from opengsq.protocols.trackmania_nations import TrackmaniaNations

from discord_gameserver_notifier.discovery.protocols.common import ServerResponse
from discord_gameserver_notifier.discovery.protocols.trackmania_nations import TrackmaniaNationsProtocol
from discord_gameserver_notifier.discovery.server_info_wrapper import ServerInfoWrapper


# opengsq >= 3.7 implements the native TrackMania query
NATIVE_QUERY = hasattr(TrackmaniaNations, "parse_server_info")

# Server info reply captured from a real server (request id 0x00413DD5)
SERVER_INFO_REPLY = bytes.fromhex(
    "9b0000008303681ac2009b0000000a0700000006000000d53d41008b5c00000b2d1d641dac2e09"
    "0900000050432d636539623063050000002353525623500204000106000600094402074b617761"
    "626f6e6761075001075374616469756d0100002c6c0001ffffffff940602e09304000178030001"
    "080000004230322d526163657a710000b9020079020374040b000040070000005374616469756d"
    "110000"
)


def make_server_info(**overrides):
    """Create a ServerInfo-like object as returned by opengsq."""
    values = dict(
        name="$o$f00Kawa$fffbonga",
        map="B02-Race",
        players=1,
        max_players=6,
        game_mode="TimeAttack",
        environment="Stadium",
        password_protected=False,
        ladder_server=False,
        comment="",
        version=None,
        spectators=0,
        max_spectators=6,
        spectator_password_protected=False,
        time_limit=300000,
        nb_laps=0,
        points_limit=0,
        pack_mask="Stadium",
        server_login="PC-ce9b0c",
        player_list=[SimpleNamespace(name="$f00Kawabonga", ladder_ranking=-1)],
        challenges=[
            SimpleNamespace(name="B02-Race"),
            SimpleNamespace(name="$oB03-Race"),
        ],
    )
    values.update(overrides)
    return SimpleNamespace(**values)


class TestInfoDict:
    """Conversion of the opengsq result into the DGN info dictionary."""

    def test_strips_formatting_codes(self):
        info = TrackmaniaNationsProtocol._build_info_dict(make_server_info())

        assert info['hostname'] == "Kawabonga"
        assert info['name_raw'] == "$o$f00Kawa$fffbonga"
        assert info['player_names'] == ["Kawabonga"]
        assert info['next_maps'] == ["B03-Race"]
        assert info['game'] == "Trackmania Nations Forever"

    def test_united_pack_mask(self):
        info = TrackmaniaNationsProtocol._build_info_dict(make_server_info(pack_mask="United"))

        assert info['game'] == "Trackmania United Forever"

    def test_works_with_old_opengsq_result(self):
        old_result = SimpleNamespace(
            name="Kawabonga", map="B02-Race", players=1, max_players=6, game_mode="Unknown",
            environment="Stadium", password_protected=False, ladder_server=False,
            comment=None, version=None,
        )

        info = TrackmaniaNationsProtocol._build_info_dict(old_result)

        assert info['hostname'] == "Kawabonga"
        assert info['max_spectators'] == 0
        assert info['next_maps'] == []


class TestDiscordFields:
    """Discord embed fields of Trackmania servers."""

    def fields(self, **overrides):
        info = TrackmaniaNationsProtocol._build_info_dict(make_server_info(**overrides))
        fields = TrackmaniaNationsProtocol().get_discord_fields(info)
        return {field['name']: field['value'] for field in fields}

    def test_public_time_attack_server(self):
        fields = self.fields()

        assert fields['🎮 Spielmodus'] == "TimeAttack (5:00)"
        assert fields['🔐 Server-Typ'] == "Public"
        assert fields['👀 Zuschauer'] == "0/6"
        assert fields['🗺️ Nächste Maps'] == "B03-Race"

    @pytest.mark.parametrize("overrides, expected", [
        ({'password_protected': True}, "Password Protected"),
        ({'spectator_password_protected': True}, "Spectator Password"),
        ({'ladder_server': True}, "Ladder"),
    ])
    def test_server_type(self, overrides, expected):
        assert self.fields(**overrides)['🔐 Server-Typ'] == expected

    def test_rounds_points_limit(self):
        fields = self.fields(game_mode="Rounds", time_limit=0, points_limit=50)

        assert fields['🎮 Spielmodus'] == "Rounds (50 Punkte)"


def test_wrapper_standardizes_trackmania_server():
    info = TrackmaniaNationsProtocol._build_info_dict(make_server_info())
    response = ServerResponse("192.168.1.50", 2350, "trackmania_nations", info, 0.01)

    result = ServerInfoWrapper().standardize_server_response(response)

    assert result.name == "Kawabonga"
    assert result.game == "Trackmania Nations Forever"
    assert result.map == "B02-Race"
    assert (result.players, result.max_players) == (1, 6)
    assert result.additional_info['game_mode'] == "TimeAttack"


async def start_fake_server(reply):
    """Start a TCP server that answers the two query messages with reply(request_id)."""

    async def handle(reader, writer):
        try:
            payloads = []
            for _ in range(2):
                length = struct.unpack("<I", await reader.readexactly(4))[0]
                payloads.append((await reader.readexactly(length))[6:])
            writer.write(reply(struct.unpack_from("<I", payloads[1], 8)[0]))
            await writer.drain()
        finally:
            writer.close()

    return await asyncio.start_server(handle, "127.0.0.1", 0)


@pytest.mark.skipif(not NATIVE_QUERY, reason="requires opengsq with the native TrackMania query")
@pytest.mark.asyncio
async def test_scan_finds_trackmania_server():
    _, payload = TrackmaniaNations.decode_message(SERVER_INFO_REPLY[4:])
    info_data = payload[16:]

    def reply(request_id):
        data = struct.pack("<IIII", 7, 6, request_id, len(info_data)) + info_data
        return TrackmaniaNations.build_message(0x03, data)

    protocol = TrackmaniaNationsProtocol(timeout=2.0)
    server = await start_fake_server(reply)
    protocol.protocol_config['port'] = server.sockets[0].getsockname()[1]

    async with server:
        servers = await protocol.scan_servers(["127.0.0.1/32"])

    assert len(servers) == 1
    assert servers[0].server_info['hostname'] == "Kawabonga"
    assert servers[0].server_info['map'] == "B02-Race"
    assert servers[0].server_info['game_mode'] == "TimeAttack"


@pytest.mark.skipif(not NATIVE_QUERY, reason="requires opengsq with the native TrackMania query")
@pytest.mark.asyncio
async def test_scan_ignores_other_services():
    protocol = TrackmaniaNationsProtocol(timeout=2.0)
    server = await start_fake_server(lambda request_id: b"HTTP/1.0 400 Bad Request\r\n\r\n#SRV#")
    protocol.protocol_config['port'] = server.sockets[0].getsockname()[1]

    async with server:
        servers = await protocol.scan_servers(["127.0.0.1/32"])

    assert servers == []
