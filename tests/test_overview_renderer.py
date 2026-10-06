"""
Tests for the Discord server overview renderer (Components V2 payloads).
"""

import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from discord_gameserver_notifier.database.models import GameServerModel
from discord_gameserver_notifier.discord.overview_renderer import (
    IS_COMPONENTS_V2,
    MAX_COMPONENTS,
    MAX_TEXT_LENGTH,
    OverviewOptions,
    build_overview_payload,
    build_paused_payload,
    count_components,
    escape_markdown,
    render_overview,
    text_length,
)

NOW = datetime(2026, 10, 6, 14, 30, 0)


def make_server(name="Test Server", game="Counter-Strike: Source", game_type="source",
                ip="10.10.100.20", port=27015, players=12, max_players=32, map_name="de_dust2",
                password=False, failed_attempts=0, last_seen=NOW):
    return GameServerModel(ip_address=ip, port=port, name=name, game=game, game_type=game_type,
                           players=players, max_players=max_players, map_name=map_name,
                           password_protected=password, failed_attempts=failed_attempts,
                           last_seen=last_seen)


def texts(payload):
    """All text display contents of a payload."""
    return [c['content'] for c in payload['components'][0]['components'] if c['type'] == 10]


def all_text(pages):
    return "\n".join(t for page in pages for t in texts(page))


class TestPayloadStructure:

    def test_empty_overview(self):
        pages = build_overview_payload([], NOW)
        assert len(pages) == 1
        page = pages[0]
        assert page['flags'] == IS_COMPONENTS_V2
        assert 'content' not in page and 'embeds' not in page
        assert page['allowed_mentions'] == {'parse': []}
        assert "Aktuell sind keine Gameserver online." in all_text(pages)
        assert "0 Server · 0 Spieler" in texts(page)[-1]

    def test_single_server(self):
        pages = build_overview_payload([make_server()], NOW)
        text = all_text(pages)
        assert "## 🎮 Gameserver-Übersicht" in text
        assert "### 🎮 Counter-Strike: Source" in text
        assert "🟢 **Test Server**" in text
        assert "👥 12/32" in text
        assert "🗺️ de\\_dust2" in text
        assert "`10.10.100.20:27015`" in text
        assert f"<t:{int(NOW.timestamp())}:t>" in texts(pages[0])[-1]

    def test_custom_title(self):
        pages = build_overview_payload([], NOW, OverviewOptions(title="LAN 2026"))
        assert texts(pages[0])[0] == "## LAN 2026"

    def test_map_placeholder_and_unknown_max_players(self):
        text = all_text(build_overview_payload([make_server(map_name="Unknown", max_players=0, players=4)], NOW))
        assert "🗺️" not in text
        assert "👥 4 ·" in text

    def test_password_marker(self):
        assert "🔒" in all_text(build_overview_payload([make_server(password=True)], NOW))

    def test_name_is_stripped(self):
        assert "**Gamie**" in all_text(build_overview_payload([make_server(name=" Gamie ")], NOW))

    def test_ipv6_address(self):
        text = all_text(build_overview_payload([make_server(ip="fe80::1")], NOW))
        assert "`[fe80::1]:27015`" in text

    def test_groups_by_game_in_stable_order(self):
        servers = [
            make_server(name="b", game="TrackMania Sunrise", game_type="trackmania_sunrise"),
            make_server(name="z", game="Counter-Strike: Source"),
            make_server(name="a", game="Counter-Strike: Source", ip="10.10.100.21"),
        ]
        shuffled = servers[:]
        random.Random(1).shuffle(shuffled)
        assert build_overview_payload(servers, NOW) == build_overview_payload(shuffled, NOW)
        text = all_text(build_overview_payload(servers, NOW))
        assert text.index("Counter-Strike") < text.index("TrackMania")
        assert text.index("**a**") < text.index("**z**")
        assert "### 🏁 TrackMania Sunrise" in text


class TestEscaping:

    def test_markdown_mentions_links_newlines(self):
        nasty = "**x** _y_ ~~z~~ ||s|| `c` [l](http://e) <@1> @everyone #h\nsecond"
        escaped = escape_markdown(nasty, 200)
        assert "\n" not in escaped
        assert "**" not in escaped.replace("\\*", "")
        assert "@everyone" not in escaped
        assert "http://" not in escaped
        assert "\\[l\\]\\(" in escaped

    def test_bidi_and_control_characters_removed(self):
        escaped = escape_markdown("abc\u202edef\u0007", 50)
        assert "\u202e" not in escaped and "\u0007" not in escaped

    def test_truncation(self):
        assert escape_markdown("x" * 100, 10) == "x" * 9 + "…"

    def test_server_name_in_payload_is_escaped(self):
        text = all_text(build_overview_payload([make_server(name="@everyone **hi**")], NOW))
        assert "@everyone" not in text
        assert "\\*\\*hi\\*\\*" in text


class TestStaleServers:

    def test_stale_server_marked(self):
        stale = make_server(name="old", failed_attempts=2, last_seen=NOW - timedelta(minutes=5), players=5)
        pages = build_overview_payload([make_server(), stale], NOW)
        text = all_text(pages)
        assert "🟡 **old**" in text
        assert "zuletzt gesehen" in text
        footer = texts(pages[-1])[-1]
        assert "2 Server · 12 Spieler · 1 nicht erreichbar" in footer

    def test_stale_server_hidden(self):
        stale = make_server(name="old", failed_attempts=2)
        text = all_text(build_overview_payload([make_server(), stale], NOW, OverviewOptions(show_stale=False)))
        assert "old" not in text
        assert "1 Server" in text


class TestPagination:

    def test_many_servers_respect_discord_limits(self):
        servers = [make_server(name="N" * 55 + f"{i:03d}", game=f"Game {i % 7}", ip=f"10.0.{i // 250}.{i % 250}",
                               map_name="m" * 60)
                   for i in range(300)]
        pages = build_overview_payload(servers, NOW, OverviewOptions(max_pages=50))
        assert len(pages) > 1
        for page in pages:
            assert count_components(page['components']) <= MAX_COMPONENTS
            assert text_length(page) <= MAX_TEXT_LENGTH
        text = all_text(pages)
        for i in range(300):
            assert text.count("N" * 55 + f"{i:03d}**") == 1
        assert texts(pages[0])[0].endswith(f"(1/{len(pages)})")
        assert "Stand:" in texts(pages[-1])[-1]
        assert all("Stand:" not in t for page in pages[:-1] for t in texts(page))
        assert "(Forts.)" in text

    def test_many_small_groups_respect_component_limit(self):
        servers = [make_server(name=f"s{i}", game=f"Game {i:03d}") for i in range(60)]
        pages = build_overview_payload(servers, NOW, OverviewOptions(max_pages=50))
        assert len(pages) >= 2
        for page in pages:
            assert count_components(page['components']) <= MAX_COMPONENTS

    def test_max_pages_cap(self):
        servers = [make_server(name="N" * 100 + str(i), ip=f"10.0.{i // 250}.{i % 250}") for i in range(300)]
        pages = build_overview_payload(servers, NOW, OverviewOptions(max_pages=2))
        assert len(pages) == 2
        text = all_text(pages)
        shown = text.count("🟢")
        assert f"… und {300 - shown} weitere Server" in text
        for page in pages:
            assert count_components(page['components']) <= MAX_COMPONENTS
            assert text_length(page) <= MAX_TEXT_LENGTH


class TestSignature:

    def test_signature_independent_of_time(self):
        servers = [make_server()]
        first = render_overview(servers, NOW)
        second = render_overview(servers, NOW + timedelta(minutes=10))
        assert first.signature == second.signature
        assert first.pages != second.pages

    def test_signature_changes_with_players(self):
        assert render_overview([make_server(players=1)], NOW).signature != \
            render_overview([make_server(players=2)], NOW).signature


def test_paused_payload():
    payload = build_paused_payload(NOW)
    assert payload['flags'] == IS_COMPONENTS_V2
    assert 'content' not in payload
    assert "Übersicht pausiert" in all_text([payload])
    assert count_components(payload['components']) <= MAX_COMPONENTS
