# TDS Proxy for SAP ASE/IQ

A Python implementation of a TDS (Tabular Data Stream) protocol proxy server for SAP ASE (Adaptive Server Enterprise) and SAP IQ databases.

## Features

- **TDS 5.0 Protocol Support**: Full implementation of the Sybase TDS protocol
- **Transparent Proxying**: Forward client connections to backend databases
- **Multiple Backends**: Route to different ASE/IQ servers based on configuration
- **Query Interception**: Optionally intercept and modify SQL queries
- **Query Logging**: Audit trail of all executed queries
- **Connection Pooling**: Efficient backend connection management
- **SSL/TLS Support**: Secure connections to backend servers
- **Async I/O**: High-performance asyncio-based implementation

## Requirements

- Python 3.8+
- PyYAML

## Installation

```bash
# Clone the repository
git clone https://github.com/example/tds-proxy.git
cd tds-proxy

# Install dependencies
pip install -r tds_proxy/requirements.txt

# Or install as package
pip install .
```

## Quick Start

### 1. Generate Configuration

```bash
python -m tds_proxy --generate-config > config.yaml
```

### 2. Edit Configuration

```yaml
# config.yaml
proxy:
  host: "0.0.0.0"
  port: 5000
  default_backend: "ase_primary"
  log_queries: true

backends:
  ase_primary:
    host: "ase-server.example.com"
    port: 5000
    type: "ase"
    database: "master"
  
  iq_analytics:
    host: "iq-server.example.com"
    port: 2638
    type: "iq"
    database: "analytics"
```

### 3. Start the Proxy

```bash
python -m tds_proxy -c config.yaml
```

### 4. Connect with a Client

Configure your client (DBeaver, isql, etc.) to connect to the proxy:

- **Host**: localhost (or proxy server IP)
- **Port**: 5000 (or configured port)
- **Server Name**: Name of the backend (e.g., `ase_primary`)

## Command Line Usage

```bash
# Start with config file
python -m tds_proxy -c config.yaml

# Start with command line arguments
python -m tds_proxy \
  --port 5000 \
  --backend ase_primary:db.example.com:5000:ase \
  --backend iq_analytics:iq.example.com:2638:iq \
  --default-backend ase_primary \
  --log-queries

# Show help
python -m tds_proxy --help

# Generate sample config
python -m tds_proxy generate-config
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-c, --config` | Path to YAML configuration file |
| `-H, --host` | Listen address (default: 0.0.0.0) |
| `-p, --port` | Listen port (default: 5000) |
| `-b, --backend` | Backend server (name:host:port[:type]) |
| `-d, --default-backend` | Default backend name |
| `-m, --mode` | Proxy mode: transparent, intercept, multiplex |
| `-q, --log-queries` | Log all SQL queries |
| `-l, --log-level` | Logging level (DEBUG, INFO, WARNING, ERROR) |

## Configuration Reference

### Proxy Settings

```yaml
proxy:
  host: "0.0.0.0"           # Listen address
  port: 5000                 # Listen port
  server_name: "TDS_Proxy"   # Server name for clients
  default_backend: "primary" # Default backend
  mode: "transparent"        # transparent, intercept, multiplex
  max_clients: 100           # Maximum concurrent clients
  client_timeout: 3600       # Client timeout in seconds
  packet_size: 4096          # TDS packet size
  log_queries: false         # Log SQL queries
  log_level: "INFO"          # Logging level
```

### Backend Settings

```yaml
backends:
  my_server:
    host: "db.example.com"   # Server hostname/IP
    port: 5000               # Server port
    type: "ase"              # ase or iq
    database: "master"       # Default database
    ssl: false               # Use SSL
    ssl_verify: true         # Verify SSL certificates
    ssl_ca_cert: ""          # Path to CA certificate
    connect_timeout: 30      # Connection timeout
    read_timeout: 300        # Read timeout
    packet_size: 4096        # Packet size
    charset: "utf8"          # Character set
    username: ""             # Override username
    password: ""             # Override password
```

## Programmatic Usage

### Basic Proxy

```python
import asyncio
from tds_proxy import TDSProxy, ProxyConfig, BackendConfig

# Configure backend
backend = BackendConfig(
    name="my_ase",
    host="ase-server.example.com",
    port=5000
)

# Create proxy config
config = ProxyConfig(
    listen_port=5000,
    backends={"my_ase": backend},
    default_backend="my_ase"
)

# Start proxy
proxy = TDSProxy(config)
asyncio.run(proxy.start())
```

### Query Interception

```python
from tds_proxy import TDSProxy, ProxyConfig, QueryRewriter

# Create rewriter
rewriter = QueryRewriter()
rewriter.add_rule("SELECT *", "SELECT /* audited */ *")

# Add to proxy
proxy = TDSProxy(config)
proxy.add_query_interceptor(rewriter.intercept)

asyncio.run(proxy.start())
```

### Custom Query Handler

```python
async def audit_query(sql: str, session) -> str:
    # Log query
    print(f"User {session.login_info.username}: {sql}")
    
    # Optionally modify
    if "DROP TABLE" in sql.upper():
        raise ValueError("DROP TABLE not allowed")
    
    return sql  # Return modified or original

proxy.add_query_interceptor(audit_query)
```

### Direct Backend Connection

```python
from tds_proxy import BackendConnection, BackendConfig

config = BackendConfig(
    name="my_ase",
    host="ase-server.example.com",
    port=5000
)

async def query_database():
    conn = BackendConnection(config)
    
    if await conn.connect():
        if await conn.login("username", "password", "database"):
            response = await conn.execute("SELECT @@version")
            print(response)
        
        await conn.disconnect()

asyncio.run(query_database())
```

## TDS Protocol Reference

### Packet Structure

```
+--------+--------+--------+--------+--------+--------+--------+--------+
|  Type  | Status |      Length     |     Channel     | Pkt#   | Window |
+--------+--------+--------+--------+--------+--------+--------+--------+
|                           Data (variable)                              |
+------------------------------------------------------------------------+
```

### Packet Types

| Type | Value | Description |
|------|-------|-------------|
| QUERY | 0x01 | SQL query |
| LOGIN | 0x02 | Login packet |
| RPC | 0x03 | Remote procedure call |
| REPLY | 0x04 | Server response |
| CANCEL | 0x06 | Cancel request |
| BULK | 0x07 | Bulk insert |
| NORMAL | 0x0F | Token stream |

### Token Types

| Token | Value | Description |
|-------|-------|-------------|
| DONE | 0xFD | Command complete |
| ERROR | 0xAA | Error message |
| INFO | 0xAB | Info message |
| LOGINACK | 0xAD | Login acknowledgment |
| ROW | 0xD1 | Data row |
| RESULT | 0xEE | Result set header |
| ENVCHANGE | 0xE3 | Environment change |
| CAPABILITY | 0xE2 | Capability exchange |

## Client Compatibility

Tested with:

- **DBeaver** (all versions)
- **Azure Data Studio** (with Sybase extension)
- **isql** (Sybase command line)
- **DbVisualizer**
- **SQuirreL SQL**
- **Custom applications** using jTDS, FreeTDS, ct-lib

## Troubleshooting

### Connection Refused

Check that:
1. The proxy is running (`ps aux | grep tds_proxy`)
2. The port is not blocked by firewall
3. Backend servers are accessible

### Login Failed

Check that:
1. Username/password are correct
2. The server name matches a configured backend
3. Backend server allows connections from proxy host

### Query Timeout

Adjust timeouts in configuration:
```yaml
backends:
  my_server:
    connect_timeout: 60
    read_timeout: 600
```

### Debug Mode

Enable debug logging:
```bash
python -m tds_proxy -c config.yaml -l DEBUG
```

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│  TDS Proxy  │────▶│  ASE / IQ   │
│  (DBeaver)  │◀────│   Server    │◀────│   Server    │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ Query Log / │
                    │   Audit     │
                    └─────────────┘
```

## License

MIT License

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting pull requests.

## See Also

- [SAP ASE Documentation](https://help.sap.com/docs/SAP_ASE)
- [SAP IQ Documentation](https://help.sap.com/docs/SAP_IQ)
- [TDS Protocol Specification](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/)
- [FreeTDS Documentation](https://www.freetds.org/)
