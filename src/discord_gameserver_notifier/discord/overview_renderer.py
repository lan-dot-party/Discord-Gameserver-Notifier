"""
Renderer for the persistent Discord server overview.

Builds Discord "Components V2" message payloads (container + text displays)
from the active servers in the database. Pure functions without any I/O so the
layout can be unit-tested without Discord.
"""

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Discord message flag that enables layout components (Container, Text Display, ...)
IS_COMPONENTS_V2 = 1 << 15

# Discord component types
COMPONENT_CONTAINER = 17
COMPONENT_TEXT_DISPLAY = 10
COMPONENT_SEPARATOR = 14

# Discord limits for Components V2 messages
MAX_COMPONENTS = 40          # total, nested components included
MAX_TEXT_LENGTH = 4000       # across all text displays of a message
TEXT_BUDGET = 3800           # safety margin below MAX_TEXT_LENGTH
PAGE_SUFFIX_RESERVE = 10     # room for " (12/12)" in the page header

DEFAULT_ACCENT_COLOR = 0x5865F2   # Discord Blurple
PAUSED_ACCENT_COLOR = 0x99AAB5    # Grey

# Emojis per game type for the overview headings. The first seven match the
# WebhookManager embeds so both features look consistent.
OVERVIEW_GAME_EMOJIS = {
    'source': '🎮',
    'renegadex': '⚔️',
    'warcraft3': '🏰',
    'flatout2': '🏎️',
    'ut3': '🔫',
    'toxikk': '⚡',
    'cnc_generals': '🎖️',
    'aoe1': '🏛️',
    'aoe2': '🏛️',
    'avp2': '👽',
    'battlefield2': '🪖',
    'cod1': '🪖',
    'cod4': '🪖',
    'cod5': '🪖',
    'eldewrito': '🛸',
    'fear2': '👻',
    'halo1': '🛸',
    'jediknight': '⚔️',
    'quake3': '🔫',
    'ssc_tfe': '💣',
    'ssc_tse': '💣',
    'stronghold_crusader': '🏯',
    'stronghold_ce': '🏯',
    'supcom': '🚀',
    'trackmania_nations': '🏁',
    'trackmania_sunrise': '🏁',
    'default': '🎯'
}

# Map names that carry no information and are therefore hidden
MAP_PLACEHOLDERS = {'', 'unknown', 'unknown map', 'n/a', 'none', '-', '?'}

MAX_NAME_LENGTH = 64
MAX_GAME_LENGTH = 64
MAX_MAP_LENGTH = 48

_MARKDOWN_SPECIAL = re.compile(r'([\\*_~`|\[\]()<>#])')
_BIDI_AND_CONTROL = re.compile(r'[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]')
_ZWSP = '\u200b'


@dataclass(frozen=True)
class OverviewOptions:
    """Display options for the overview."""
    title: str = '🎮 Gameserver-Übersicht'
    show_stale: bool = True
    accent_color: int = DEFAULT_ACCENT_COLOR
    max_pages: int = 5


@dataclass(frozen=True)
class RenderedOverview:
    """Rendered overview pages plus a content signature (independent of the render time)."""
    pages: List[Dict[str, Any]]
    signature: str


@dataclass
class _Group:
    """All servers of one game, rendered as one text display."""
    heading: str
    entries: List[str] = field(default_factory=list)


def escape_markdown(text: Optional[str], max_len: int) -> str:
    """
    Make untrusted text (server names, maps, ...) safe for Discord markdown.

    Removes control and bidi characters, collapses whitespace, truncates,
    escapes markdown characters and defuses mentions and links.
    """
    if not text:
        return ''
    text = unicodedata.normalize('NFC', str(text))
    text = _BIDI_AND_CONTROL.sub(' ', text)
    text = ' '.join(text.split())
    if len(text) > max_len:
        text = text[:max_len - 1].rstrip() + '…'
    text = _MARKDOWN_SPECIAL.sub(r'\\\1', text)
    text = text.replace('@', '@' + _ZWSP)
    text = text.replace('://', ':' + _ZWSP + '//')
    return text


def discord_timestamp(dt: datetime, style: str = 't') -> str:
    """Format a datetime as Discord timestamp markup (shown in each viewer's timezone)."""
    return f"<t:{int(dt.timestamp())}:{style}>"


def count_components(components: List[Dict[str, Any]]) -> int:
    """Count components recursively, nested ones included (Discord's 40 component limit)."""
    total = 0
    for component in components:
        total += 1
        total += count_components(component.get('components', []))
        if 'accessory' in component:
            total += 1
    return total


def _utf16_len(text: str) -> int:
    """Length as Discord counts it (UTF-16 code units)."""
    return len(text.encode('utf-16-le')) // 2


def text_length(payload: Dict[str, Any]) -> int:
    """Total text length of all text displays in a payload."""
    def _walk(components: List[Dict[str, Any]]) -> int:
        length = 0
        for component in components:
            if component.get('type') == COMPONENT_TEXT_DISPLAY:
                length += _utf16_len(component.get('content', ''))
            length += _walk(component.get('components', []))
        return length
    return _walk(payload.get('components', []))


def _is_stale(server) -> bool:
    """A server that was not found in the last scan(s) but is not cleaned up yet."""
    return (getattr(server, 'failed_attempts', 0) or 0) > 0


def _format_address(server) -> str:
    ip = server.ip_address or '?'
    if ':' in ip:  # IPv6
        ip = f'[{ip}]'
    return f"`{ip}:{server.port}`"


def _format_entry(server) -> str:
    """Two lines per server: status + name, then players, map and address."""
    name = escape_markdown(server.name, MAX_NAME_LENGTH) or 'Unbenannter Server'
    first_line = f"{'🟡' if _is_stale(server) else '🟢'} **{name}**"
    if server.password_protected:
        first_line += ' 🔒'
    if _is_stale(server) and server.last_seen:
        first_line += f" · zuletzt gesehen {discord_timestamp(server.last_seen)}"

    players = server.players or 0
    details = [f"👥 {players}/{server.max_players}" if (server.max_players or 0) > 0 else f"👥 {players}"]
    map_name = (server.map_name or '').strip()
    if map_name.casefold() not in MAP_PLACEHOLDERS:
        details.append(f"🗺️ {escape_markdown(map_name, MAX_MAP_LENGTH)}")
    details.append(_format_address(server))
    return f"{first_line}\n{' · '.join(details)}"


def _sort_key(server) -> Tuple[str, str, str, int]:
    return (
        (server.game or '').casefold(),
        (server.name or '').strip().casefold(),
        server.ip_address or '',
        server.port or 0
    )


def _build_groups(servers: Sequence) -> List[_Group]:
    groups: Dict[str, _Group] = {}
    for server in sorted(servers, key=_sort_key):
        game = escape_markdown(server.game, MAX_GAME_LENGTH) or 'Unbekanntes Spiel'
        key = (server.game or '').casefold()
        if key not in groups:
            emoji = OVERVIEW_GAME_EMOJIS.get(server.game_type, OVERVIEW_GAME_EMOJIS['default'])
            groups[key] = _Group(heading=f"### {emoji} {game}")
        groups[key].entries.append(_format_entry(server))
    return list(groups.values())


def _text_display(content: str) -> Dict[str, Any]:
    return {'type': COMPONENT_TEXT_DISPLAY, 'content': content}


def _separator(divider: bool = True) -> Dict[str, Any]:
    return {'type': COMPONENT_SEPARATOR, 'divider': divider, 'spacing': 1}


def _wrap(components: List[Dict[str, Any]], accent_color: int) -> Dict[str, Any]:
    return {
        'flags': IS_COMPONENTS_V2,
        'allowed_mentions': {'parse': []},
        'components': [{
            'type': COMPONENT_CONTAINER,
            'accent_color': accent_color,
            'components': components
        }]
    }


def _paginate(blocks: List[Tuple[str, int]], footer: str, header: str,
              max_pages: int) -> List[List[str]]:
    """
    Distribute text blocks over pages so that every page stays within Discord's
    component and text limits. Each page is: container, header, then
    (separator + text display) per block, and the footer (separator + text) on the last page.
    
    Args:
        blocks: (text, number of servers in the block)
        footer: Footer text (reserved on every page, only shown on the last one)
        header: Header text
        max_pages: Maximum number of pages; the rest is summarised in a notice
    """
    # Fixed cost per page: container + header text + footer separator + footer text
    fixed_components = 4
    fixed_text = _utf16_len(header) + PAGE_SUFFIX_RESERVE + _utf16_len(footer)

    pages: List[List[Tuple[str, int]]] = [[]]
    used_components = fixed_components
    used_text = fixed_text
    for block in blocks:
        cost_text = _utf16_len(block[0])
        if pages[-1] and (used_components + 2 > MAX_COMPONENTS or used_text + cost_text > TEXT_BUDGET):
            pages.append([])
            used_components = fixed_components
            used_text = fixed_text
        pages[-1].append(block)
        used_components += 2
        used_text += cost_text

    if len(pages) > max_pages:
        total = sum(count for _, count in blocks)
        pages = pages[:max_pages]
        last = pages[-1]
        notice_cost = 80
        while last and (fixed_text + sum(_utf16_len(text) for text, _ in last) + notice_cost > TEXT_BUDGET
                        or fixed_components + 2 * (len(last) + 1) > MAX_COMPONENTS):
            last.pop()
        shown = sum(count for page in pages for _, count in page)
        last.append((f"… und {total - shown} weitere Server (Anzeigelimit erreicht)", 0))

    return [[text for text, _ in page] for page in pages]


def _split_group(group: _Group) -> List[Tuple[str, int]]:
    """
    Turn a game group into one or more text blocks (text, server count). Large groups
    are split so that every block fits a page on its own; follow-ups are marked "(Forts.)".
    """
    limit = TEXT_BUDGET // 2
    blocks: List[Tuple[str, int]] = []
    current = group.heading
    count = 0
    for entry in group.entries:
        candidate = f"{current}\n{entry}" if count == 0 else f"{current}\n\n{entry}"
        if count > 0 and _utf16_len(candidate) > limit:
            blocks.append((current, count))
            current = f"{group.heading} (Forts.)\n{entry}"
            count = 1
            continue
        current = candidate
        count += 1
    blocks.append((current, count))
    return blocks


def build_overview_payload(servers: Sequence, now: Optional[datetime],
                           options: OverviewOptions = OverviewOptions()) -> List[Dict[str, Any]]:
    """
    Build the overview message payloads (one per page).

    Args:
        servers: Active GameServerModel objects
        now: Render time for the footer; None renders a time-independent footer
             (used for the change signature)
        options: Display options

    Returns:
        List of Discord message payloads (Components V2)
    """
    visible = [s for s in servers if options.show_stale or not _is_stale(s)]
    online = [s for s in visible if not _is_stale(s)]
    stale_count = len(visible) - len(online)

    footer = (f"-# Stand: {discord_timestamp(now)} ({discord_timestamp(now, 'R')})"
              if now else "-# Stand: –")
    footer += f" · {len(visible)} Server · {sum(s.players or 0 for s in online)} Spieler"
    if stale_count:
        footer += f" · {stale_count} nicht erreichbar"

    header = f"## {options.title}"

    if not visible:
        blocks = [("Aktuell sind keine Gameserver online.", 0)]
    else:
        blocks = [block for group in _build_groups(visible) for block in _split_group(group)]

    pages = _paginate(blocks, footer, header, options.max_pages)

    payloads = []
    for index, page_blocks in enumerate(pages):
        page_header = header if len(pages) == 1 else f"{header} ({index + 1}/{len(pages)})"
        components = [_text_display(page_header)]
        for block in page_blocks:
            components.append(_separator())
            components.append(_text_display(block))
        if index == len(pages) - 1:
            components.append(_separator(divider=False))
            components.append(_text_display(footer))
        payloads.append(_wrap(components, options.accent_color))
    return payloads


def render_overview(servers: Sequence, now: datetime,
                    options: OverviewOptions = OverviewOptions()) -> RenderedOverview:
    """Render the overview pages plus a signature that only changes with the shown data."""
    pages = build_overview_payload(servers, now, options)
    stable = build_overview_payload(servers, None, options)
    signature = hashlib.sha256(
        json.dumps(stable, sort_keys=True, ensure_ascii=False).encode('utf-8')
    ).hexdigest()
    return RenderedOverview(pages=pages, signature=signature)


def build_paused_payload(stopped_at: datetime, options: OverviewOptions = OverviewOptions()) -> Dict[str, Any]:
    """Payload shown while DGN is stopped (replaces the first overview page on shutdown)."""
    return _wrap([
        _text_display(f"## {options.title}"),
        _separator(),
        _text_display(
            f"⏸️ **Übersicht pausiert** – DGN gestoppt um {discord_timestamp(stopped_at)}.\n"
            f"-# Die Liste wird beim nächsten Start automatisch aktualisiert."
        )
    ], PAUSED_ACCENT_COLOR)
