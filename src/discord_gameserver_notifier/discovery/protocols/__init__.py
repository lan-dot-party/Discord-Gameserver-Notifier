"""
Protocol implementations for various game servers.
"""

from .common import ServerResponse, BroadcastResponseProtocol
from .source import SourceProtocol
from .renegadex import RenegadeXProtocol
from .flatout2 import Flatout2Protocol
from .ut3 import UT3Protocol
from .warcraft3 import Warcraft3Protocol
from .toxikk import ToxikkProtocol
# from .eldewrito import ElDewritoProtocol  # Commented out - protocol not yet merged in main opengsq-python repo

__all__ = [
    'ServerResponse',
    'BroadcastResponseProtocol',
    'SourceProtocol',
    'RenegadeXProtocol', 
    'Flatout2Protocol',
    'UT3Protocol',
    'Warcraft3Protocol',
    'ToxikkProtocol',
    # 'ElDewritoProtocol'  # Commented out - protocol not yet merged in main opengsq-python repo
] 