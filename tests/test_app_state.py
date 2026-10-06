"""
Tests for the app_state key/value store and get_all_active_servers(raise_errors=...).

Uses a file database (tmp_path): DatabaseManager opens a new connection per
call, so ':memory:' would lose the data between calls.
"""

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from discord_gameserver_notifier.database.database_manager import DatabaseManager


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "gameservers.db")


def test_state_default_and_roundtrip(db_path):
    db = DatabaseManager(db_path)
    assert db.get_state("missing") is None
    assert db.get_state("missing", "fallback") == "fallback"
    assert db.set_state("key", "one")
    assert db.get_state("key") == "one"
    assert db.set_state("key", "two")
    assert db.get_state("key") == "two"
    assert db.delete_state("key")
    assert db.get_state("key") is None


def test_state_persists_across_instances(db_path):
    DatabaseManager(db_path).set_state("discord_overview", '{"message_ids": ["1"]}')
    assert DatabaseManager(db_path).get_state("discord_overview") == '{"message_ids": ["1"]}'


def test_app_state_table_added_to_existing_database(db_path):
    DatabaseManager(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("DROP TABLE app_state")
    db = DatabaseManager(db_path)
    assert db.set_state("key", "value")
    assert db.get_state("key") == "value"


def test_get_all_active_servers_raise_errors(db_path):
    db = DatabaseManager(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("DROP TABLE server_history")
        conn.execute("DROP TABLE gameservers")
    assert db.get_all_active_servers() == []
    with pytest.raises(sqlite3.Error):
        db.get_all_active_servers(raise_errors=True)
