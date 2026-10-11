"""
Tests for the UT99 (Unreal Tournament 1999) discovery protocol.
"""

import asyncio
import sys
from pathlib import Path

import pytest

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from discord_gameserver_notifier.discovery.protocols.common import ServerResponse
from discord_gameserver_notifier.discovery.protocols.ut99 import UT99Protocol
from discord_gameserver_notifier.discovery.server_info_wrapper import ServerInfoWrapper

INFO_QUERY = b"\\info\\"
RULES_QUERY = b"\\rules\\"
PLAYERS_QUERY = b"\\players\\"

# Replies of an empty UT99 dedicated server (version 469), captured on the LAN
INFO_REPLY = (
    b"\\hostname\\LinuxGSM\\hostport\\7777\\maptitle\\Deck #16 ][\\mapname\\DM-Deck16]["
    b"\\gametype\\DeathMatchPlus\\numplayers\\0\\maxplayers\\10\\gamemode\\openplaying"
    b"\\gamever\\469\\minnetver\\432\\worldlog\\true\\wantworldlog\\true\\queryid\\6.1\\final\\"
)
RULES_REPLY = (
    b"\\listenserver\\False\\password\\False\\timelimit\\0\\fraglimit\\30\\minplayers\\0"
    b"\\changelevels\\True\\tournament\\False\\gamestyle\\Hardcore\\mutators\\ \\queryid\\21.1\\final\\"
)
MUTATORS_REPLY = b"\\EnabledMutators\\ \\queryid\\28.1\\final\\"

# Replies of a UT99 listen server (version 436) with one player and the
# InstaGib mutator. Its rules reply does not name the mutators.
INFO_REPLY_436 = (
    b"\\hostname\\Another UT Server\\hostport\\7777\\maptitle\\The Pit of Agony\\mapname\\DM-Agony"
    b"\\gametype\\DeathMatchPlus\\numplayers\\1\\maxplayers\\16\\gamemode\\openplaying"
    b"\\gamever\\436\\minnetver\\400\\worldlog\\true\\wantworldlog\\true\\queryid\\1.1\\final\\"
)
RULES_REPLY_436 = (
    b"\\listenserver\\True\\password\\False\\timelimit\\0\\fraglimit\\30\\minplayers\\0"
    b"\\changelevels\\True\\tournament\\False\\gamestyle\\Classic\\queryid\\9.1\\final\\"
)
PLAYERS_REPLY_436 = (
    b"\\player_0\\Gamienator\\frags_0\\0\\ping_0\\0\\team_0\\255\\mesh_0\\Male Soldier"
    b"\\skin_0\\SoldierSkins.Gard\\face_0\\SoldierSkins.Drake\\ngsecret_0\\false\\queryid\\3.1\\final\\"
)
MUTATORS_REPLY_436 = b"\\EnabledMutators\\InstaGib\\queryid\\38.1\\final\\"

# The first rules reply of the version 436 server after a map change
RULES_REPLY_436_FIRST = RULES_REPLY_436.replace(b"\\listenserver", b"\\mutators\\InstaGib\\listenserver", 1)

# Replies of the version 436 server running a team deathmatch with a game
# password and the Instant Rockets mutator
INFO_REPLY_TEAM = INFO_REPLY_436.replace(b"DeathMatchPlus\\numplayers\\1", b"TeamGamePlus\\numplayers\\0")
RULES_REPLY_TEAM = (
    b"\\listenserver\\False\\password\\True\\timelimit\\0\\goalteamscore\\30\\minplayers\\0"
    b"\\changelevels\\True\\maxteams\\2\\balanceteams\\True\\playersbalanceteams\\True"
    b"\\friendlyfire\\0%\\tournament\\False\\gamestyle\\Classic\\queryid\\2.1\\final\\"
)
MUTATORS_REPLY_TEAM = b"\\EnabledMutators\\Instant Rockets\\queryid\\4.1\\final\\"

INFO = {
    'hostname': 'LinuxGSM',
    'hostport': '7777',
    'maptitle': 'Deck #16 ][',
    'mapname': 'DM-Deck16][',
    'gametype': 'DeathMatchPlus',
    'numplayers': '0',
    'maxplayers': '10',
    'gamever': '469',
}

RULES = {
    'listenserver': 'False',
    'password': 'False',
    'timelimit': '20',
    'fraglimit': '30',
    'gamestyle': 'Hardcore',
    'mutators': '',
}


class TestBuildInfoDict:
    def test_maps_info_and_rules(self):
        info = UT99Protocol._build_info_dict(INFO, RULES, [], None, 7778)

        assert info['hostname'] == "LinuxGSM"
        assert info['map'] == "DM-Deck16]["
        assert info['map_title'] == "Deck #16 ]["
        assert info['game_mode'] == "Deathmatch"
        assert info['game_class'] == "DeathMatchPlus"
        assert (info['players'], info['max_players']) == (0, 10)
        assert info['version'] == "469"
        assert (info['goal_score'], info['time_limit']) == (30, 20)
        assert info['password_protected'] is False
        assert info['mutators'] == []
        assert (info['game_port'], info['query_port']) == (7777, 7778)

    def test_password_marks_server_protected(self):
        info = UT99Protocol._build_info_dict(INFO, {**RULES, 'password': 'True'}, [], None, 7778)

        assert info['password_protected'] is True

    def test_missing_rules(self):
        info = UT99Protocol._build_info_dict({**INFO, 'gametype': 'MyCustomGame'}, {}, [], None, 7778)

        assert info['game_mode'] == "MyCustomGame"
        assert info['password_protected'] is False
        assert (info['goal_score'], info['time_limit']) == (0, 0)
        assert info['mutators'] == []

    def test_team_game_uses_team_goal(self):
        # Team games do not report a frag limit
        rules = {'password': 'False', 'timelimit': '0', 'goalteamscore': '3'}
        info = UT99Protocol._build_info_dict({**INFO, 'gametype': 'CTFGame'}, rules, [], None, 7778)

        assert info['game_mode'] == "Capture the Flag"
        assert info['goal_score'] == 3

    def test_missing_host_port_falls_back_to_query_port(self):
        info = UT99Protocol._build_info_dict({'hostname': 'LinuxGSM'}, {}, [], None, 7788)

        assert info['game_port'] == 7787

    def test_queried_mutators_win_over_rules(self):
        info = UT99Protocol._build_info_dict(INFO, RULES, [], "InstaGib, No Redeemer", 7778)

        assert info['mutators'] == ["InstaGib", "No Redeemer"]

    def test_mutators_from_rules_without_mutators_reply(self):
        info = UT99Protocol._build_info_dict(INFO, {**RULES, 'mutators': 'InstaGib'}, [], None, 7778)

        assert info['mutators'] == ["InstaGib"]

    def test_player_names(self):
        players = [{'player': 'Gamienator', 'frags': '0'}, {'frags': '3'}, {'player': 'Xan'}]
        info = UT99Protocol._build_info_dict(INFO, RULES, players, None, 7778)

        assert info['player_names'] == ["Gamienator", "Xan"]


def test_discord_fields():
    info = UT99Protocol._build_info_dict(INFO, {**RULES, 'password': 'True'}, [], "InstaGib", 7778)
    fields = {field['name']: field['value'] for field in UT99Protocol().get_discord_fields(info)}

    assert fields['🎮 Spielmodus'] == "Deathmatch (30 Punkte, 20 min)"
    assert fields['🧩 Mutatoren'] == "InstaGib"
    # Already shown by the standard embed fields
    assert '🔐 Server-Typ' not in fields
    assert '📦 Version' not in fields


def test_discord_fields_without_mutators_and_time_limit():
    info = UT99Protocol._build_info_dict(INFO, {**RULES, 'timelimit': '0'}, [], " ", 7778)
    fields = {field['name']: field['value'] for field in UT99Protocol().get_discord_fields(info)}

    assert fields == {'🎮 Spielmodus': "Deathmatch (30 Punkte)"}


def test_wrapper_standardizes_ut99_server():
    info = UT99Protocol._build_info_dict({**INFO, 'numplayers': '3'}, RULES, [], "InstaGib", 7778)
    response = ServerResponse("10.10.100.212", 7777, "ut99", info, 0.01)

    result = ServerInfoWrapper(protocols={'ut99': UT99Protocol()}).standardize_server_response(response)

    assert result.name == "LinuxGSM"
    assert result.game == "Unreal Tournament 99"
    assert result.map == "DM-Deck16]["
    assert (result.players, result.max_players) == (3, 10)
    assert result.version == "469"
    assert result.port == 7777
    assert result.additional_info['query_port'] == 7778
    assert result.additional_info['mutators'] == ["InstaGib"]
    assert result.discord_fields


class FakeQueryServer(asyncio.DatagramProtocol):
    """Query port of a UT99 server: answers every query it has a reply for."""

    def __init__(self, replies):
        self.replies = replies
        self.received = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.received.append(data)

        if self.replies.get(data) is not None:
            self.transport.sendto(self.replies[data], addr)


class FakeBeacon(asyncio.DatagramProtocol):
    """Beacon port of a UT99 server: answers the LAN query with the query port."""

    def __init__(self, reply, replies=1):
        self.reply = reply
        self.replies = replies

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if data == UT99Protocol.DISCOVERY_QUERY:
            for _ in range(self.replies):
                self.transport.sendto(self.reply, addr)


async def start_fake_server(info=INFO_REPLY, rules=RULES_REPLY, players=None,
                            mutators=MUTATORS_REPLY, beacon_reply=None, replies=1):
    """Start the query and the beacon sockets of a fake server."""
    loop = asyncio.get_running_loop()
    query_transport, query_server = await loop.create_datagram_endpoint(
        lambda: FakeQueryServer({
            INFO_QUERY: info,
            RULES_QUERY: rules,
            PLAYERS_QUERY: players,
            UT99Protocol.MUTATORS_QUERY: mutators,
        }),
        local_addr=("127.0.0.1", 0)
    )
    query_port = query_transport.get_extra_info("sockname")[1]
    beacon_transport, _ = await loop.create_datagram_endpoint(
        lambda: FakeBeacon(beacon_reply or b"ut %d" % query_port, replies), local_addr=("127.0.0.1", 0)
    )
    return query_server, (query_transport, beacon_transport)


def make_scanning_protocol(beacon_port):
    protocol = UT99Protocol(timeout=0.5)
    protocol.protocol_config.update(beacon_ports=[beacon_port], broadcast_timeout=0.3, global_broadcast=False)
    return protocol


async def scan(transports):
    query_transport, beacon_transport = transports
    protocol = make_scanning_protocol(beacon_transport.get_extra_info("sockname")[1])

    try:
        return await protocol.scan_servers(["127.0.0.1/32"])
    finally:
        query_transport.close()
        beacon_transport.close()


@pytest.mark.asyncio
async def test_scan_finds_empty_ut99_server():
    query_server, transports = await start_fake_server()
    query_port = transports[0].get_extra_info("sockname")[1]

    servers = await scan(transports)

    assert len(servers) == 1
    assert servers[0].game_type == "ut99"
    # Reported with the game port players connect to
    assert (servers[0].ip_address, servers[0].port) == ("127.0.0.1", 7777)
    assert servers[0].server_info['query_port'] == query_port
    assert servers[0].server_info['hostname'] == "LinuxGSM"
    assert servers[0].server_info['map'] == "DM-Deck16]["
    assert servers[0].server_info['version'] == "469"
    assert servers[0].server_info['password_protected'] is False
    assert servers[0].server_info['mutators'] == []
    # No players query to an empty server
    assert PLAYERS_QUERY not in query_server.received


@pytest.mark.asyncio
async def test_scan_detects_password():
    _, transports = await start_fake_server(
        rules=RULES_REPLY.replace(b"\\password\\False", b"\\password\\True")
    )

    servers = await scan(transports)

    assert servers[0].server_info['password_protected'] is True


@pytest.mark.asyncio
async def test_scan_reads_players_and_mutators_of_436_server():
    _, transports = await start_fake_server(
        info=INFO_REPLY_436, rules=RULES_REPLY_436, players=PLAYERS_REPLY_436, mutators=MUTATORS_REPLY_436
    )

    servers = await scan(transports)

    assert servers[0].server_info['hostname'] == "Another UT Server"
    assert servers[0].server_info['version'] == "436"
    assert servers[0].server_info['players'] == 1
    assert servers[0].server_info['player_names'] == ["Gamienator"]
    # Not part of the rules reply, only of the game property
    assert servers[0].server_info['mutators'] == ["InstaGib"]


@pytest.mark.asyncio
async def test_scan_reads_protected_team_game():
    _, transports = await start_fake_server(
        info=INFO_REPLY_TEAM, rules=RULES_REPLY_TEAM, mutators=MUTATORS_REPLY_TEAM
    )

    servers = await scan(transports)

    assert servers[0].server_info['game_mode'] == "Team Deathmatch"
    assert servers[0].server_info['goal_score'] == 30
    assert servers[0].server_info['password_protected'] is True
    assert servers[0].server_info['mutators'] == ["Instant Rockets"]


@pytest.mark.asyncio
async def test_scan_uses_rules_mutators_without_mutators_reply():
    _, transports = await start_fake_server(rules=RULES_REPLY_436_FIRST, mutators=None)

    servers = await scan(transports)

    assert servers[0].server_info['mutators'] == ["InstaGib"]


@pytest.mark.asyncio
async def test_scan_reports_server_without_rules_reply():
    _, transports = await start_fake_server(rules=None)

    servers = await scan(transports)

    assert len(servers) == 1
    assert servers[0].server_info['hostname'] == "LinuxGSM"
    assert servers[0].server_info['goal_score'] == 0


@pytest.mark.asyncio
async def test_scan_reports_server_once_for_repeated_replies():
    _, transports = await start_fake_server(replies=3)

    servers = await scan(transports)

    assert len(servers) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("beacon_reply", [b"unreal 7778", b"ut", b"ut 0", b"ut 99999", b"not a ut99 server"])
async def test_scan_ignores_other_beacon_replies(beacon_reply):
    query_server, transports = await start_fake_server(beacon_reply=beacon_reply)

    servers = await scan(transports)

    assert servers == []
    assert query_server.received == []
