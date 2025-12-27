"""
TDS Backend Connection Module
=============================

Handles connections to SAP ASE and IQ backend servers.
"""

import ssl
import asyncio
from dataclasses import dataclass
from typing import Optional, Dict, Any
from enum import Enum
import logging

from .tds import (
    TDSPacket, TDSHeader, TDSPacketType, TDSPacketStatus,
    TDSLogin, TDSTokenParser, TDSToken,
    hexdump
)

logger = logging.getLogger(__name__)


class DatabaseType(Enum):
    """Supported database types"""
    ASE = "ase"
    IQ = "iq"
    GENERIC_SYBASE = "sybase"


@dataclass
class BackendConfig:
    """Configuration for a backend database server"""
    name: str
    host: str
    port: int
    database_type: DatabaseType = DatabaseType.ASE
    default_database: str = ""
    use_ssl: bool = False
    ssl_verify: bool = True
    ssl_ca_cert: Optional[str] = None
    connect_timeout: float = 30.0
    read_timeout: float = 300.0
    packet_size: int = 4096
    charset: str = "utf8"
    
    # Optional authentication override
    username: Optional[str] = None
    password: Optional[str] = None


@dataclass
class ConnectionState:
    """State of a backend connection"""
    connected: bool = False
    authenticated: bool = False
    database: str = ""
    server_name: str = ""
    tds_version: tuple = (5, 0, 0, 0)
    packet_size: int = 4096
    charset: str = "utf8"
    language: str = ""
    spid: int = 0  # Server process ID


class BackendConnection:
    """
    Manages a connection to a backend SAP ASE or IQ server.
    
    This class handles:
    - TCP/SSL connection management
    - TDS protocol communication
    - Login and authentication
    - Query execution
    - Result set handling
    """
    
    def __init__(self, config: BackendConfig):
        self.config = config
        self.state = ConnectionState()
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._lock = asyncio.Lock()
        self._packet_number = 0
    
    async def connect(self) -> bool:
        """Establish connection to backend server"""
        try:
            logger.info(f"Connecting to {self.config.name} at {self.config.host}:{self.config.port}")
            
            # Create SSL context if needed
            ssl_context = None
            if self.config.use_ssl:
                ssl_context = ssl.create_default_context()
                if not self.config.ssl_verify:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                elif self.config.ssl_ca_cert:
                    ssl_context.load_verify_locations(self.config.ssl_ca_cert)
            
            # Open connection
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.config.host,
                    self.config.port,
                    ssl=ssl_context
                ),
                timeout=self.config.connect_timeout
            )
            
            self.state.connected = True
            logger.info(f"Connected to {self.config.name}")
            return True
            
        except asyncio.TimeoutError:
            logger.error(f"Connection timeout to {self.config.name}")
            return False
        except Exception as e:
            logger.error(f"Connection error to {self.config.name}: {e}")
            return False
    
    async def disconnect(self):
        """Close connection to backend server"""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception as e:
                logger.warning(f"Error closing connection: {e}")
        
        self.state = ConnectionState()
        self._reader = None
        self._writer = None
        logger.info(f"Disconnected from {self.config.name}")
    
    async def login(self, username: str, password: str, 
                    database: str = "", appname: str = "TDS_Proxy",
                    hostname: str = "") -> bool:
        """
        Perform TDS login to backend server.
        
        Returns True if login successful, False otherwise.
        """
        if not self.state.connected:
            logger.error("Cannot login - not connected")
            return False
        
        # Use config override if provided
        if self.config.username:
            username = self.config.username
        if self.config.password:
            password = self.config.password
        if not database and self.config.default_database:
            database = self.config.default_database
        
        # Build login packet
        login = TDSLogin(
            hostname=hostname or "proxy",
            username=username,
            password=password,
            appname=appname,
            servername=self.config.name,
            database=database,
            packet_size=self.config.packet_size
        )
        
        login_data = login.pack()
        packet = TDSPacket.create(TDSPacketType.TDS_LOGIN, login_data)
        
        # Send login packet
        await self._send_packet(packet)
        
        # Read response
        response = await self._receive_packet()
        if not response:
            logger.error("No response to login")
            return False
        
        # Parse login response
        return await self._process_login_response(response)
    
    async def _process_login_response(self, response: TDSPacket) -> bool:
        """Process login response from server"""
        tokens = TDSTokenParser.parse_tokens(response.data)
        
        login_ack = False
        error_msg = None
        
        for token in tokens:
            if token['type'] == TDSToken.TDS_LOGINACK:
                login_ack = True
                self.state.authenticated = True
                logger.info(f"Login acknowledged by {self.config.name}")
                
            elif token['type'] == TDSToken.TDS_CAPABILITY:
                logger.debug("Received capability token")
                
            elif token['type'] == TDSToken.TDS_ENVCHANGE:
                self._process_envchange(token)
                
            elif token['type'] in (TDSToken.TDS_ERROR, TDSToken.TDS_EED):
                if token.get('payload'):
                    error_msg = self._parse_error(token['payload'])
                    logger.error(f"Login error: {error_msg}")
                    
            elif token['type'] == TDSToken.TDS_DONE:
                if token.get('status', 0) & 0x0002:  # Error flag
                    if not error_msg:
                        error_msg = "Login failed with unspecified error"
        
        if error_msg:
            logger.error(f"Login failed: {error_msg}")
            return False
        
        return login_ack
    
    def _process_envchange(self, token: Dict[str, Any]):
        """Process environment change token"""
        payload = token.get('payload', b'')
        if len(payload) < 3:
            return
        
        change_type = payload[0]
        
        try:
            new_len = payload[1]
            new_val = payload[2:2+new_len].decode('utf-8', errors='ignore')
            
            if change_type == 1:  # Database
                self.state.database = new_val
                logger.debug(f"Database changed to: {new_val}")
            elif change_type == 2:  # Language
                self.state.language = new_val
            elif change_type == 3:  # Charset
                self.state.charset = new_val
            elif change_type == 4:  # Packet size
                try:
                    self.state.packet_size = int(new_val)
                except ValueError:
                    pass
        except Exception as e:
            logger.warning(f"Error processing envchange: {e}")
    
    def _parse_error(self, payload: bytes) -> str:
        """Parse error message from EED token"""
        try:
            offset = 0
            msg_number = int.from_bytes(payload[offset:offset+4], 'little')
            offset += 4
            payload[offset]
            offset += 1
            severity = payload[offset]
            offset += 1
            
            # Skip TDS status and transaction state
            offset += 3
            
            # Message length and text
            if offset + 2 <= len(payload):
                msg_len = int.from_bytes(payload[offset:offset+2], 'little')
                offset += 2
                message = payload[offset:offset+msg_len].decode('utf-8', errors='ignore')
                return f"[{msg_number}] Severity {severity}: {message}"
        except Exception as e:
            logger.warning(f"Error parsing error message: {e}")
        
        return "Unknown error"
    
    async def execute(self, sql: str) -> bytes:
        """
        Execute a SQL query and return raw response data.
        
        Returns the raw TDS response for forwarding to client.
        """
        if not self.state.authenticated:
            raise RuntimeError("Not authenticated")
        
        async with self._lock:
            # Build and send query packet
            query_data = sql.encode('utf-8')
            packet = TDSPacket.create(TDSPacketType.TDS_QUERY, query_data)
            
            await self._send_packet(packet)
            
            # Collect all response packets
            response_data = bytearray()
            
            while True:
                response = await self._receive_packet()
                if not response:
                    break
                
                # Add the complete packet (header + data)
                response_data.extend(response.pack())
                
                # Check if this is the last packet
                if response.header.status & TDSPacketStatus.TDS_BUFSTAT_EOM:
                    break
            
            return bytes(response_data)
    
    async def forward_raw(self, data: bytes) -> bytes:
        """
        Forward raw TDS data to backend and return response.
        
        Used for proxying client requests directly.
        """
        if not self._writer:
            raise RuntimeError("Not connected")
        
        async with self._lock:
            # Send raw data
            self._writer.write(data)
            await self._writer.drain()
            
            # Collect response
            response_data = bytearray()
            
            while True:
                response = await self._receive_packet()
                if not response:
                    break
                
                response_data.extend(response.pack())
                
                if response.header.status & TDSPacketStatus.TDS_BUFSTAT_EOM:
                    break
            
            return bytes(response_data)
    
    async def _send_packet(self, packet: TDSPacket):
        """Send a TDS packet to the backend"""
        if not self._writer:
            raise RuntimeError("Not connected")
        
        data = packet.pack()
        logger.debug(f"Sending {len(data)} bytes to {self.config.name}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"\n{hexdump(data[:128], 'TX: ')}")
        
        self._writer.write(data)
        await self._writer.drain()
    
    async def _receive_packet(self) -> Optional[TDSPacket]:
        """Receive a TDS packet from the backend"""
        if not self._reader:
            return None
        
        try:
            # Read header
            header_data = await asyncio.wait_for(
                self._reader.readexactly(TDSHeader.HEADER_SIZE),
                timeout=self.config.read_timeout
            )
            
            header = TDSHeader.unpack(header_data)
            
            # Read payload
            payload_len = header.length - TDSHeader.HEADER_SIZE
            if payload_len > 0:
                payload_data = await asyncio.wait_for(
                    self._reader.readexactly(payload_len),
                    timeout=self.config.read_timeout
                )
            else:
                payload_data = b''
            
            packet = TDSPacket(header=header, data=payload_data)
            
            logger.debug(f"Received {header.length} bytes from {self.config.name}")
            if logger.isEnabledFor(logging.DEBUG):
                full_data = header_data + payload_data
                logger.debug(f"\n{hexdump(full_data[:128], 'RX: ')}")
            
            return packet
            
        except asyncio.TimeoutError:
            logger.warning(f"Read timeout from {self.config.name}")
            return None
        except asyncio.IncompleteReadError:
            logger.warning(f"Connection closed by {self.config.name}")
            self.state.connected = False
            return None
        except Exception as e:
            logger.error(f"Error receiving packet: {e}")
            return None
    
    @property
    def is_connected(self) -> bool:
        return self.state.connected
    
    @property
    def is_authenticated(self) -> bool:
        return self.state.authenticated


class ConnectionPool:
    """
    Connection pool for backend database servers.
    
    Manages multiple connections to backend servers and handles
    connection reuse and cleanup.
    """
    
    def __init__(self, config: BackendConfig, max_connections: int = 10):
        self.config = config
        self.max_connections = max_connections
        self._connections: list[BackendConnection] = []
        self._available: asyncio.Queue = asyncio.Queue()
        self._lock = asyncio.Lock()
        self._closed = False
    
    async def acquire(self, username: str, password: str, 
                      database: str = "") -> BackendConnection:
        """
        Acquire a connection from the pool.
        
        If no connections are available, creates a new one.
        """
        if self._closed:
            raise RuntimeError("Pool is closed")
        
        # Try to get an existing connection
        try:
            conn = self._available.get_nowait()
            if conn.is_authenticated:
                return conn
        except asyncio.QueueEmpty:
            pass
        
        # Create new connection if under limit
        async with self._lock:
            if len(self._connections) < self.max_connections:
                conn = BackendConnection(self.config)
                if await conn.connect():
                    if await conn.login(username, password, database):
                        self._connections.append(conn)
                        return conn
                    else:
                        await conn.disconnect()
                raise RuntimeError(f"Failed to connect to {self.config.name}")
        
        # Wait for available connection
        conn = await self._available.get()
        return conn
    
    async def release(self, conn: BackendConnection):
        """Release a connection back to the pool"""
        if conn.is_connected and conn.is_authenticated:
            await self._available.put(conn)
        else:
            async with self._lock:
                if conn in self._connections:
                    self._connections.remove(conn)
            await conn.disconnect()
    
    async def close(self):
        """Close all connections in the pool"""
        self._closed = True
        
        async with self._lock:
            for conn in self._connections:
                await conn.disconnect()
            self._connections.clear()
        
        # Clear the queue
        while not self._available.empty():
            try:
                self._available.get_nowait()
            except asyncio.QueueEmpty:
                break
