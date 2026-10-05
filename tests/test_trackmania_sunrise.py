"""
Tests for the Trackmania Original/Sunrise/Nations ESWC discovery protocol.
"""

import asyncio
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from discord_gameserver_notifier.discovery.protocols import trackmania_sunrise
from discord_gameserver_notifier.discovery.protocols.common import ServerResponse
from discord_gameserver_notifier.discovery.protocols.trackmania_sunrise import TrackmaniaSunriseProtocol
from discord_gameserver_notifier.discovery.server_info_wrapper import ServerInfoWrapper

TrackmaniaSunrise = trackmania_sunrise.TrackmaniaSunrise

# opengsq with the TrackMania Sunrise query (not yet released on PyPI)
requires_opengsq = pytest.mark.skipif(
    TrackmaniaSunrise is None, reason="requires opengsq with TrackmaniaSunrise support"
)

# Reply of a TrackMania Sunrise eXtreme dedicated server to request id 0x1234
SERVER_INFO_REPLY = bytes.fromhex(
    "330200008303adf73b18770200000006040000000600000034120000670200000704650a0a2e09"
    "0f480200074445534b544f502d4a424b4c354a3005000000235352562300600002200020001244"
    "020f53756e72697365204c414e2053657276657275031e580708547261636b4d616e696120f004"
    "0345787472656d90050401e093040036144408080b0000004e69676874466c75000d580106ee98"
    "0000ab050000075803054361725061726b0c580203f6900000d104b80204585261636530346404"
    "0005e83401009d0700000a00000041717561536368656d65095c1005c07f01009f0500006c0106"
    "4772616e64507269786806053c9b0000720500006c1a03536e616b6508540503d87c00004f06bc"
    "08074368616f73204172656168040678690000d50200000e54040b506172616469736549736c61"
    "6e647c240274d10000f42b590237681105e4b001004907000064170954756e6e656c4566666563"
    "74600a02fc20010022c80d07536d616c6c2052696e67640505384a0000c2030000782005416572"
    "69616c204c792273600202a8610000635c07741506446f776e746f776e03402303cecc00004906"
    "bc1c075370656564576176650e501502e0a50100b1c0290456696c6c616765781f0286c9000026"
    "543e7c0806486170707942617902580502e86e0300a42b250332540d0400e0b00000c707b80b05"
    "4d61676e697475649c2b0c1e1d0100900500000b000000557020412c207812741f03307500005b"
    "032aac060a3502000000722d0100b8070000110000"
)


def make_server_info(**overrides):
    """Create a ServerInfo-like object as returned by opengsq."""
    values = dict(
        name="$o$f00Sunrise $fffLAN",
        map="$oNightFlight",
        environment="Island",
        mood="Night",
        players=2,
        max_players=32,
        spectators=1,
        max_spectators=32,
        game_mode="TimeAttack",
        time_limit=300000,
        nb_laps=0,
        points_limit=0,
        password_protected=False,
        spectator_password_protected=False,
        ladder_server=False,
        server_login="DESKTOP-JBKL5J0",
        comment="$iLAN-Party",
        player_list=[SimpleNamespace(name="$f00Gamie", ladder_ranking=0)],
        challenges=[SimpleNamespace(name="NightFlight"), SimpleNamespace(name="$oCarPark")],
        nb_challenges=54,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def make_session(**overrides):
    """Create a SessionInfo-like object as returned by opengsq."""
    values = dict(
        game_id="TmSunrise",
        game="TrackMania Sunrise",
        version="1.043",
        host_name="DESKTOP-JBKL5J0",
        server_port=2350,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


@requires_opengsq
class TestInfoDict:
    """Conversion of the opengsq results into the DGN info dictionary."""

    def test_strips_formatting_codes(self):
        info = TrackmaniaSunriseProtocol._build_info_dict(make_server_info(), make_session())

        assert info['hostname'] == "Sunrise LAN"
        assert info['name_raw'] == "$o$f00Sunrise $fffLAN"
        assert info['map'] == "NightFlight"
        assert info['comment'] == "LAN-Party"
        assert info['player_names'] == ["Gamie"]
        assert info['next_maps'] == ["CarPark"]

    def test_game_from_session(self):
        info = TrackmaniaSunriseProtocol._build_info_dict(
            make_server_info(),
            make_session(game_id="TmOriginal", game="TrackMania Original", version="1.0"),
        )

        assert (info['game_id'], info['game'], info['version']) == (
            "TmOriginal", "TrackMania Original", "1.0"
        )

    def test_falls_back_to_host_name(self):
        info = TrackmaniaSunriseProtocol._build_info_dict(make_server_info(name="$o"), make_session())

        assert info['hostname'] == "DESKTOP-JBKL5J0"


@requires_opengsq
def test_discord_fields():
    info = TrackmaniaSunriseProtocol._build_info_dict(
        make_server_info(password_protected=True), make_session()
    )
    fields = {field['name']: field['value']
              for field in TrackmaniaSunriseProtocol().get_discord_fields(info)}

    assert fields['🏟️ Environment'] == "Island (Night)"
    assert fields['🎮 Spielmodus'] == "TimeAttack (5:00)"
    assert fields['🔐 Server-Typ'] == "Password Protected"
    assert fields['👀 Zuschauer'] == "1/32"
    assert fields['🗺️ Nächste Maps'] == "CarPark"
    assert fields['💬 Kommentar'] == "LAN-Party"


def test_broadcast_addresses():
    protocol = TrackmaniaSunriseProtocol()

    addresses = protocol._broadcast_addresses(
        ["10.10.100.0/23", "10.10.101.0/24", "invalid", "fd00::/64", "192.168.1.7/32"]
    )

    assert addresses == ["255.255.255.255", "10.10.101.255", "192.168.1.7"]


@pytest.mark.asyncio
async def test_scan_without_opengsq_support(monkeypatch):
    monkeypatch.setattr(trackmania_sunrise, "TrackmaniaSunrise", None)

    assert await TrackmaniaSunriseProtocol().scan_servers(["127.0.0.1/32"]) == []


@requires_opengsq
def test_wrapper_standardizes_trackmania_sunrise_server():
    info = TrackmaniaSunriseProtocol._build_info_dict(make_server_info(), make_session())
    response = ServerResponse("10.10.101.4", 2350, "trackmania_sunrise", info, 0.01)

    result = ServerInfoWrapper().standardize_server_response(response)

    assert result.name == "Sunrise LAN"
    assert result.game == "TrackMania Sunrise"
    assert result.version == "1.043"
    assert result.map == "NightFlight"
    assert (result.players, result.max_players) == (2, 32)
    assert result.additional_info['game_id'] == "TmSunrise"
    assert (result.additional_info['environment'], result.additional_info['mood']) == ("Island", "Night")
    assert result.additional_info['nb_challenges'] == 54


class FakeSessionServer(asyncio.DatagramProtocol):
    """Answers LAN session queries for one game id, like a real server."""

    def __init__(self, game_id, port_holder):
        self.game_id = game_id
        self.port_holder = port_holder

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        _, payload = TrackmaniaSunrise.decode_message(data)
        length = struct.unpack_from("<I", payload)[0]
        game_id = payload[4:4 + length].decode()
        nonce = struct.unpack_from("<I", payload, len(payload) - 4)[0]

        if game_id != self.game_id:
            return

        def string(text):
            return struct.pack("<I", len(text)) + text.encode()

        address = bytes([1, 0, 0, 127]) + struct.pack("<H", self.port_holder[0])
        reply = struct.pack("<I", nonce) + string("GameNet") + string(game_id)
        reply += string("1.043") + string("LANBOX") + address + address

        self.transport.sendto(TrackmaniaSunrise.build_message(0x01, reply), addr)


async def start_fake_server(game_id="TmSunrise"):
    """Start a UDP session and a TCP info server on the same port."""
    _, payload = TrackmaniaSunrise.decode_message(SERVER_INFO_REPLY[4:])
    info_data = payload[16:]

    async def handle(reader, writer):
        try:
            payloads = []
            for _ in range(2):
                length = struct.unpack("<I", await reader.readexactly(4))[0]
                payloads.append((await reader.readexactly(length))[6:])
            request_id = struct.unpack_from("<I", payloads[1], 8)[0]
            reply = struct.pack("<IIII", 4, 6, request_id, len(info_data)) + info_data
            message = TrackmaniaSunrise.build_message(0x03, reply)
            writer.write(struct.pack("<I", len(message)) + message)
            await writer.drain()
        finally:
            writer.close()

    loop = asyncio.get_running_loop()
    port_holder = [0]

    for _ in range(5):
        transport, _ = await loop.create_datagram_endpoint(
            lambda: FakeSessionServer(game_id, port_holder), local_addr=("127.0.0.1", 0)
        )
        port_holder[0] = transport.get_extra_info("sockname")[1]

        try:
            server = await asyncio.start_server(handle, "127.0.0.1", port_holder[0])
            return transport, server, port_holder[0]
        except OSError:
            transport.close()

    pytest.skip("no free port for the fake server")


def make_scanning_protocol(port):
    protocol = TrackmaniaSunriseProtocol(timeout=2.0)
    protocol.protocol_config.update(
        ports=[port], broadcast_timeout=0.3, global_broadcast=False
    )
    return protocol


@requires_opengsq
@pytest.mark.asyncio
async def test_scan_finds_trackmania_sunrise_server():
    transport, server, port = await start_fake_server("TmSunrise")
    protocol = make_scanning_protocol(port)

    try:
        async with server:
            servers = await protocol.scan_servers(["127.0.0.1/32"])
    finally:
        transport.close()

    assert len(servers) == 1
    assert (servers[0].ip_address, servers[0].port) == ("127.0.0.1", port)
    assert servers[0].game_type == "trackmania_sunrise"
    assert servers[0].server_info['hostname'] == "Sunrise LAN Server"
    assert servers[0].server_info['game'] == "TrackMania Sunrise"
    assert servers[0].server_info['map'] == "NightFlight"
    assert (servers[0].server_info['environment'], servers[0].server_info['mood']) == ("Island", "Night")
    assert servers[0].server_info['nb_challenges'] == 54


@requires_opengsq
@pytest.mark.asyncio
async def test_scan_ignores_other_udp_services():
    loop = asyncio.get_running_loop()

    class Echo(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, addr):
            self.transport.sendto(b"not a trackmania server", addr)

    transport, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
    protocol = make_scanning_protocol(transport.get_extra_info("sockname")[1])

    try:
        servers = await protocol.scan_servers(["127.0.0.1/32"])
    finally:
        transport.close()

    assert servers == []


@requires_opengsq
def test_discord_fields_without_environment():
    info = TrackmaniaSunriseProtocol._build_info_dict(
        make_server_info(environment="", mood=""), make_session()
    )
    names = [field['name'] for field in TrackmaniaSunriseProtocol().get_discord_fields(info)]

    assert '🏟️ Environment' not in names
