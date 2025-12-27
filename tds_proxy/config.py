"""
Configuration Management for TDS Proxy
=======================================

Handles loading and validating proxy configuration from YAML or dict.
"""

import os
from typing import Dict, Any

from .backend import BackendConfig, DatabaseType
from .proxy import ProxyConfig, ProxyMode


def _env_var(name: str, default: str = "") -> str:
    """Get environment variable with optional default."""
    return os.environ.get(name, default)


def default_config() -> ProxyConfig:
    """
    Create the default proxy configuration.

    This is the Python equivalent of config.yaml.
    Environment variables can be used for sensitive or environment-specific values.
    """
    backends = {
        "ase_primary": BackendConfig(
            name="ase_primary",
            host=_env_var("ASE_PRIMARY_HOST", "ase-primary.example.com"),
            port=5000,
            database_type=DatabaseType.ASE,
            default_database="master",
            connect_timeout=30.0,
            read_timeout=300.0,
            packet_size=4096,
            charset="utf8",
            use_ssl=False,
            ssl_verify=True,
        ),
        "ase_secondary": BackendConfig(
            name="ase_secondary",
            host=_env_var("ASE_SECONDARY_HOST", "ase-secondary.example.com"),
            port=5000,
            database_type=DatabaseType.ASE,
            default_database="master",
            connect_timeout=30.0,
            read_timeout=300.0,
        ),
        "iq_analytics": BackendConfig(
            name="iq_analytics",
            host=_env_var("IQ_HOST", "iq-analytics.example.com"),
            port=2638,
            database_type=DatabaseType.IQ,
            default_database="analytics_db",
            use_ssl=True,
            ssl_verify=True,
            read_timeout=1800.0,  # 30 minutes for analytical queries
        ),
        "ase_dev": BackendConfig(
            name="ase_dev",
            host="localhost",
            port=5001,
            database_type=DatabaseType.ASE,
            default_database="testdb",
            connect_timeout=10.0,
            read_timeout=60.0,
        ),
    }

    return ProxyConfig(
        listen_host="0.0.0.0",
        listen_port=5000,
        server_name="TDS_Proxy",
        default_backend="ase_primary",
        mode=ProxyMode.TRANSPARENT,
        max_clients=100,
        client_timeout=3600.0,  # 1 hour
        packet_size=4096,
        log_queries=True,
        log_level="INFO",
        backends=backends,
    )


def load_config(config_path: str) -> ProxyConfig:
    """Load configuration from YAML file."""
    import yaml

    with open(config_path, 'r') as f:
        data = yaml.safe_load(f)

    return parse_config(data)


def parse_config(data: Dict[str, Any]) -> ProxyConfig:
    """Parse configuration from dictionary"""
    # Parse backends
    backends = {}
    for name, backend_data in data.get('backends', {}).items():
        backends[name] = BackendConfig(
            name=name,
            host=backend_data['host'],
            port=backend_data.get('port', 5000),
            database_type=DatabaseType(backend_data.get('type', 'ase')),
            default_database=backend_data.get('database', ''),
            use_ssl=backend_data.get('ssl', False),
            ssl_verify=backend_data.get('ssl_verify', True),
            ssl_ca_cert=backend_data.get('ssl_ca_cert'),
            connect_timeout=backend_data.get('connect_timeout', 30.0),
            read_timeout=backend_data.get('read_timeout', 300.0),
            packet_size=backend_data.get('packet_size', 4096),
            charset=backend_data.get('charset', 'utf8'),
            username=backend_data.get('username'),
            password=backend_data.get('password')
        )
    
    # Parse proxy settings
    proxy_data = data.get('proxy', {})
    
    mode = proxy_data.get('mode', 'transparent')
    if isinstance(mode, str):
        mode = ProxyMode(mode)
    
    return ProxyConfig(
        listen_host=proxy_data.get('host', '0.0.0.0'),
        listen_port=proxy_data.get('port', 5000),
        backends=backends,
        default_backend=proxy_data.get('default_backend', ''),
        mode=mode,
        server_name=proxy_data.get('server_name', 'TDS_Proxy'),
        packet_size=proxy_data.get('packet_size', 4096),
        max_clients=proxy_data.get('max_clients', 100),
        client_timeout=proxy_data.get('client_timeout', 3600.0),
        log_queries=proxy_data.get('log_queries', False),
        log_level=proxy_data.get('log_level', 'INFO')
    )


def create_sample_config() -> str:
    """Generate sample configuration YAML"""
    return """# TDS Proxy Configuration
# ========================

# Proxy server settings
proxy:
  # Bind address and port
  host: "0.0.0.0"
  port: 5000
  
  # Server name shown to clients
  server_name: "TDS_Proxy"
  
  # Default backend if client doesn't specify
  default_backend: "ase_primary"
  
  # Proxy mode: transparent, intercept, or multiplex
  mode: "transparent"
  
  # Connection settings
  max_clients: 100
  client_timeout: 3600  # seconds
  packet_size: 4096
  
  # Logging
  log_queries: false
  log_level: "INFO"

# Backend database servers
backends:
  # SAP ASE server example
  ase_primary:
    host: "ase-server.example.com"
    port: 5000
    type: "ase"
    database: "master"
    
    # Optional: SSL configuration
    ssl: false
    ssl_verify: true
    # ssl_ca_cert: "/path/to/ca-cert.pem"
    
    # Connection settings
    connect_timeout: 30
    read_timeout: 300
    packet_size: 4096
    charset: "utf8"
    
    # Optional: Override credentials
    # username: "proxy_user"
    # password: "proxy_password"
  
  # SAP IQ server example
  iq_analytics:
    host: "iq-server.example.com"
    port: 2638
    type: "iq"
    database: "analytics"
    ssl: true
    ssl_verify: true
  
  # Another ASE server
  ase_secondary:
    host: "ase-secondary.example.com"
    port: 5000
    type: "ase"
    database: "production"
"""


def save_sample_config(path: str):
    """Save sample configuration to file"""
    with open(path, 'w') as f:
        f.write(create_sample_config())


# Environment variable support
def load_config_with_env(config_path: str) -> ProxyConfig:
    """Load configuration with environment variable substitution"""
    import re
    import yaml

    with open(config_path, 'r') as f:
        content = f.read()

    # Substitute ${ENV_VAR} patterns
    def replace_env(match):
        var_name = match.group(1)
        default = match.group(3) if match.group(3) else ''
        return os.environ.get(var_name, default)

    content = re.sub(r'\$\{(\w+)(:-([^}]*))?\}', replace_env, content)

    data = yaml.safe_load(content)
    return parse_config(data)
