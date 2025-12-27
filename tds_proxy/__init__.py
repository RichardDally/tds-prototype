"""
TDS Proxy for SAP ASE and IQ
============================

A proxy server for Sybase/SAP ASE and IQ databases using the TDS protocol.
"""

from .proxy import TDSProxy, ProxyConfig, ProxyMode
from .backend import BackendConfig, BackendConnection, DatabaseType
from .config import default_config, load_config

__version__ = "1.0.0"

__all__ = [
    "TDSProxy",
    "ProxyConfig",
    "ProxyMode",
    "BackendConfig",
    "BackendConnection",
    "DatabaseType",
    "default_config",
    "load_config",
]
