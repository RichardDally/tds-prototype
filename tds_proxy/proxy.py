"""
TDS Proxy Server
================

Main proxy server that accepts client connections (e.g., DBeaver)
and forwards them to configured SAP ASE/IQ backend servers.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Callable, Awaitable, Any
from enum import Enum
import logging
import time

from .tds import (
    TDSPacket, TDSHeader, TDSPacketType, TDSPacketStatus,
    TDSLogin, TDSTokenBuilder, TDSDoneStatus
)
from .backend import BackendConfig, BackendConnection

logger = logging.getLogger(__name__)


class ProxyMode(Enum):
    """Proxy operation modes"""
    TRANSPARENT = "transparent"     # Forward everything as-is
    INTERCEPT = "intercept"         # Intercept and modify queries
    MULTIPLEX = "multiplex"         # Route to multiple backends


@dataclass
class ProxyConfig:
    """Configuration for the proxy server"""
    # Listener settings
    listen_host: str = "0.0.0.0"
    listen_port: int = 5000
    
    # Backend servers
    backends: Dict[str, BackendConfig] = field(default_factory=dict)
    default_backend: str = ""
    
    # Proxy behavior
    mode: ProxyMode = ProxyMode.TRANSPARENT
    
    # TDS settings
    server_name: str = "TDS_Proxy"
    packet_size: int = 4096
    
    # Connection limits
    max_clients: int = 100
    client_timeout: float = 3600.0  # 1 hour
    
    # Logging
    log_queries: bool = False
    log_level: str = "INFO"


class ClientSession:
    """
    Represents a connected client session.
    
    Manages the state between a client and its backend connection.
    """
    
    def __init__(self, session_id: int, reader: asyncio.StreamReader, 
                 writer: asyncio.StreamWriter, config: ProxyConfig):
        self.session_id = session_id
        self.reader = reader
        self.writer = writer
        self.config = config
        
        # Client info
        self.client_address = writer.get_extra_info('peername')
        self.login_info: Optional[TDSLogin] = None
        self.authenticated = False
        
        # Backend connection
        self.backend: Optional[BackendConnection] = None
        self.backend_name: Optional[str] = None
        
        # Session state
        self.created_at = time.time()
        self.last_activity = time.time()
        self.query_count = 0
        
        # Collected login data (may span multiple packets)
        self._login_buffer = bytearray()
    
    async def close(self):
        """Close the client session"""
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass
        
        if self.backend:
            await self.backend.disconnect()
        
        logger.info(f"Session {self.session_id} closed after {self.query_count} queries")


class TDSProxy:
    """
    TDS Proxy Server
    
    Accepts client connections and forwards them to backend SAP ASE/IQ servers.
    
    Features:
    - Transparent proxying of TDS protocol
    - Login interception for routing
    - Query logging
    - Connection pooling (optional)
    """
    
    def __init__(self, config: ProxyConfig):
        self.config = config
        self._server: Optional[asyncio.Server] = None
        self._sessions: Dict[int, ClientSession] = {}
        self._session_counter = 0
        self._lock = asyncio.Lock()
        self._running = False
        
        # Query interceptors (optional)
        self._query_interceptors: List[Callable[[str, ClientSession], Awaitable[Optional[str]]]] = []
        
        # Response interceptors (optional)
        self._response_interceptors: List[Callable[[bytes, ClientSession], Awaitable[Optional[bytes]]]] = []
    
    def add_query_interceptor(self, interceptor: Callable[[str, ClientSession], Awaitable[Optional[str]]]):
        """Add a query interceptor function"""
        self._query_interceptors.append(interceptor)
    
    def add_response_interceptor(self, interceptor: Callable[[bytes, ClientSession], Awaitable[Optional[bytes]]]):
        """Add a response interceptor function"""
        self._response_interceptors.append(interceptor)
    
    async def start(self):
        """Start the proxy server"""
        self._running = True
        
        self._server = await asyncio.start_server(
            self._handle_client,
            self.config.listen_host,
            self.config.listen_port,
            reuse_address=True
        )
        
        addr = self._server.sockets[0].getsockname()
        logger.info(f"TDS Proxy listening on {addr[0]}:{addr[1]}")
        
        async with self._server:
            await self._server.serve_forever()
    
    async def stop(self):
        """Stop the proxy server"""
        self._running = False
        
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        
        # Close all sessions
        async with self._lock:
            for session in list(self._sessions.values()):
                await session.close()
            self._sessions.clear()
        
        logger.info("TDS Proxy stopped")
    
    async def _handle_client(self, reader: asyncio.StreamReader, 
                            writer: asyncio.StreamWriter):
        """Handle a new client connection"""
        async with self._lock:
            self._session_counter += 1
            session_id = self._session_counter
        
        session = ClientSession(session_id, reader, writer, self.config)
        
        logger.info(f"New connection from {session.client_address} (session {session_id})")
        
        async with self._lock:
            self._sessions[session_id] = session
        
        try:
            await self._process_session(session)
        except Exception as e:
            logger.error(f"Session {session_id} error: {e}", exc_info=True)
        finally:
            async with self._lock:
                self._sessions.pop(session_id, None)
            await session.close()
    
    async def _process_session(self, session: ClientSession):
        """Process a client session"""
        while self._running:
            try:
                # Read packet header
                header_data = await asyncio.wait_for(
                    session.reader.readexactly(TDSHeader.HEADER_SIZE),
                    timeout=self.config.client_timeout
                )
                
                header = TDSHeader.unpack(header_data)
                
                # Read packet payload
                payload_len = header.length - TDSHeader.HEADER_SIZE
                if payload_len > 0:
                    payload_data = await session.reader.readexactly(payload_len)
                else:
                    payload_data = b''
                
                packet = TDSPacket(header=header, data=payload_data)
                session.last_activity = time.time()
                
                # Handle packet based on type
                await self._handle_packet(session, packet)
                
            except asyncio.TimeoutError:
                logger.info(f"Session {session.session_id} timed out")
                break
            except asyncio.IncompleteReadError:
                logger.info(f"Session {session.session_id} disconnected")
                break
            except Exception as e:
                logger.error(f"Error processing session {session.session_id}: {e}")
                break
    
    async def _handle_packet(self, session: ClientSession, packet: TDSPacket):
        """Handle a TDS packet from client"""
        packet_type = packet.header.packet_type
        
        logger.debug(f"Session {session.session_id}: Received packet type {packet_type}")
        
        if packet_type == TDSPacketType.TDS_LOGIN:
            await self._handle_login(session, packet)
        
        elif packet_type == TDSPacketType.TDS_QUERY:
            await self._handle_query(session, packet)
        
        elif packet_type == TDSPacketType.TDS_CANCEL:
            await self._handle_cancel(session, packet)
        
        elif packet_type == TDSPacketType.TDS_RPC:
            await self._handle_rpc(session, packet)
        
        else:
            # Forward unknown packets directly if connected
            if session.backend and session.backend.is_authenticated:
                await self._forward_to_backend(session, packet)
            else:
                logger.warning(f"Unexpected packet type {packet_type} before login")
    
    async def _handle_login(self, session: ClientSession, packet: TDSPacket):
        """Handle login packet from client"""
        # Collect login data (may span multiple packets)
        session._login_buffer.extend(packet.data)
        
        # Check if this is the last packet of the login
        if not (packet.header.status & TDSPacketStatus.TDS_BUFSTAT_EOM):
            return  # Wait for more data
        
        # Parse login packet
        try:
            login = TDSLogin.unpack(bytes(session._login_buffer))
            session.login_info = login
            session._login_buffer.clear()
            
            logger.info(
                f"Session {session.session_id}: Login from user '{login.username}' "
                f"app='{login.appname}' db='{login.database}'"
            )
            
        except Exception as e:
            logger.error(f"Failed to parse login: {e}")
            await self._send_login_error(session, "Failed to parse login packet")
            return
        
        # Determine backend based on server name or default
        backend_name = self._select_backend(login)
        
        if not backend_name or backend_name not in self.config.backends:
            await self._send_login_error(session, f"Unknown server: {login.servername}")
            return
        
        # Connect to backend
        backend_config = self.config.backends[backend_name]
        session.backend = BackendConnection(backend_config)
        session.backend_name = backend_name
        
        if not await session.backend.connect():
            await self._send_login_error(session, f"Failed to connect to {backend_name}")
            return
        
        # Forward login to backend
        login_packet = TDSPacket.create(TDSPacketType.TDS_LOGIN, login.pack())
        
        try:
            response = await session.backend.forward_raw(login_packet.pack())
            
            if response:
                # Forward login response to client
                session.writer.write(response)
                await session.writer.drain()
                
                # Check if login was successful
                if session.backend.is_authenticated:
                    session.authenticated = True
                    logger.info(f"Session {session.session_id}: Login successful to {backend_name}")
                else:
                    logger.warning(f"Session {session.session_id}: Login failed to {backend_name}")
            else:
                await self._send_login_error(session, "No response from backend")
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            await self._send_login_error(session, str(e))
    
    def _select_backend(self, login: TDSLogin) -> Optional[str]:
        """Select backend based on login info"""
        # Try to match server name
        server_name = login.servername.lower()
        
        for name, config in self.config.backends.items():
            if name.lower() == server_name:
                return name
        
        # Use database name as hint
        database = login.database.lower()
        
        for name, config in self.config.backends.items():
            if config.default_database.lower() == database:
                return name
        
        # Fall back to default
        if self.config.default_backend:
            return self.config.default_backend
        
        # Use first available backend
        if self.config.backends:
            return list(self.config.backends.keys())[0]
        
        return None
    
    async def _handle_query(self, session: ClientSession, packet: TDSPacket):
        """Handle query packet from client"""
        if not session.authenticated or not session.backend:
            await self._send_error(session, "Not authenticated")
            return
        
        # Extract SQL query
        sql = packet.data.decode('utf-8', errors='ignore')
        session.query_count += 1
        
        if self.config.log_queries:
            logger.info(f"Session {session.session_id}: Query: {sql[:200]}")
        
        # Apply query interceptors
        for interceptor in self._query_interceptors:
            try:
                modified = await interceptor(sql, session)
                if modified is not None:
                    sql = modified
            except Exception as e:
                logger.warning(f"Query interceptor error: {e}")
        
        # Forward to backend
        try:
            response = await session.backend.execute(sql)
            
            # Apply response interceptors
            for interceptor in self._response_interceptors:
                try:
                    modified = await interceptor(response, session)
                    if modified is not None:
                        response = modified
                except Exception as e:
                    logger.warning(f"Response interceptor error: {e}")
            
            # Send response to client
            if response:
                session.writer.write(response)
                await session.writer.drain()
                
        except Exception as e:
            logger.error(f"Query execution error: {e}")
            await self._send_error(session, str(e))
    
    async def _handle_cancel(self, session: ClientSession, packet: TDSPacket):
        """Handle cancel request from client"""
        logger.debug(f"Session {session.session_id}: Cancel request")
        
        if session.backend and session.backend.is_connected:
            # Forward cancel to backend
            await self._forward_to_backend(session, packet)
    
    async def _handle_rpc(self, session: ClientSession, packet: TDSPacket):
        """Handle RPC packet from client"""
        if not session.authenticated or not session.backend:
            await self._send_error(session, "Not authenticated")
            return
        
        # Forward RPC to backend
        await self._forward_to_backend(session, packet)
    
    async def _forward_to_backend(self, session: ClientSession, packet: TDSPacket):
        """Forward a packet to the backend and relay response"""
        if not session.backend:
            return
        
        try:
            response = await session.backend.forward_raw(packet.pack())
            
            if response:
                session.writer.write(response)
                await session.writer.drain()
                
        except Exception as e:
            logger.error(f"Forward error: {e}")
            await self._send_error(session, str(e))
    
    async def _send_login_error(self, session: ClientSession, message: str):
        """Send login error response to client"""
        response = bytearray()
        
        # Error token
        response.extend(TDSTokenBuilder.build_error(
            msg_number=18456,
            state=1,
            severity=14,
            message=message,
            server_name=self.config.server_name
        ))
        
        # Done token with error flag
        response.extend(TDSTokenBuilder.build_done(
            status=TDSDoneStatus.TDS_DONE_ERROR | TDSDoneStatus.TDS_DONE_FINAL
        ))
        
        packet = TDSPacket.create(TDSPacketType.TDS_REPLY, bytes(response))
        
        session.writer.write(packet.pack())
        await session.writer.drain()
    
    async def _send_error(self, session: ClientSession, message: str):
        """Send error response to client"""
        response = bytearray()
        
        # Error token
        response.extend(TDSTokenBuilder.build_error(
            msg_number=50000,
            state=1,
            severity=16,
            message=message,
            server_name=self.config.server_name
        ))
        
        # Done token
        response.extend(TDSTokenBuilder.build_done(
            status=TDSDoneStatus.TDS_DONE_ERROR | TDSDoneStatus.TDS_DONE_FINAL
        ))
        
        packet = TDSPacket.create(TDSPacketType.TDS_REPLY, bytes(response))
        
        session.writer.write(packet.pack())
        await session.writer.drain()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get proxy statistics"""
        return {
            'active_sessions': len(self._sessions),
            'total_sessions': self._session_counter,
            'backends': list(self.config.backends.keys()),
            'running': self._running
        }


# =============================================================================
# Query Rewriting Example
# =============================================================================

class QueryRewriter:
    """
    Example query rewriter for common transformations.
    
    Can be used to:
    - Translate SQL dialects
    - Add audit columns
    - Enforce row-level security
    """
    
    def __init__(self):
        self.rules: List[tuple] = []
    
    def add_rule(self, pattern: str, replacement: str):
        """Add a simple text replacement rule"""
        self.rules.append((pattern, replacement))
    
    async def intercept(self, sql: str, session: ClientSession) -> Optional[str]:
        """Apply rewrite rules to query"""
        modified = sql
        
        for pattern, replacement in self.rules:
            modified = modified.replace(pattern, replacement)
        
        if modified != sql:
            logger.debug(f"Query rewritten: {sql[:100]} -> {modified[:100]}")
            return modified
        
        return None


# =============================================================================
# Audit Logger Example
# =============================================================================

class AuditLogger:
    """
    Example audit logger for query logging.
    """
    
    def __init__(self, log_file: Optional[str] = None):
        self.log_file = log_file
        self._file = None
    
    async def log_query(self, sql: str, session: ClientSession) -> None:
        """Log query without modifying it"""
        log_entry = {
            'timestamp': time.time(),
            'session_id': session.session_id,
            'user': session.login_info.username if session.login_info else 'unknown',
            'database': session.login_info.database if session.login_info else '',
            'backend': session.backend_name,
            'query': sql[:1000],  # Truncate long queries
            'client': session.client_address
        }
        
        logger.info(f"AUDIT: {log_entry}")
        
        return None  # Don't modify query
