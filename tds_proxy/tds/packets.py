"""
TDS Packet Structures
=====================

Core packet structures for TDS protocol communication.
"""

import struct
import logging
from dataclasses import dataclass, field
from typing import Tuple

from .constants import TDSPacketStatus, TDSToken

logger = logging.getLogger(__name__)


@dataclass
class TDSHeader:
    """TDS Packet Header (8 bytes)"""
    packet_type: int
    status: int
    length: int
    channel: int = 0
    packet_number: int = 0
    window: int = 0

    HEADER_SIZE = 8

    def pack(self) -> bytes:
        """Pack header to bytes"""
        return struct.pack(
            '>BBHHBB',
            self.packet_type,
            self.status,
            self.length,
            self.channel,
            self.packet_number,
            self.window
        )

    @classmethod
    def unpack(cls, data: bytes) -> 'TDSHeader':
        """Unpack header from bytes"""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Header requires {cls.HEADER_SIZE} bytes, got {len(data)}")

        packet_type, status, length, channel, packet_number, window = struct.unpack(
            '>BBHHBB', data[:cls.HEADER_SIZE]
        )
        return cls(
            packet_type=packet_type,
            status=status,
            length=length,
            channel=channel,
            packet_number=packet_number,
            window=window
        )


@dataclass
class TDSPacket:
    """Complete TDS Packet"""
    header: TDSHeader
    data: bytes

    def pack(self) -> bytes:
        """Pack complete packet to bytes"""
        return self.header.pack() + self.data

    @classmethod
    def unpack(cls, data: bytes) -> 'TDSPacket':
        """Unpack complete packet from bytes"""
        header = TDSHeader.unpack(data)
        packet_data = data[TDSHeader.HEADER_SIZE:header.length]
        return cls(header=header, data=packet_data)

    @classmethod
    def create(cls, packet_type: int, data: bytes, status: int = TDSPacketStatus.TDS_BUFSTAT_EOM) -> 'TDSPacket':
        """Create a new TDS packet"""
        length = TDSHeader.HEADER_SIZE + len(data)
        header = TDSHeader(
            packet_type=packet_type,
            status=status,
            length=length
        )
        return cls(header=header, data=data)


@dataclass
class TDSLogin:
    """TDS Login Packet (TDS 5.0 - Sybase)"""
    hostname: str = ""
    username: str = ""
    password: str = ""
    appname: str = "TDS_Proxy"
    servername: str = ""
    library: str = "TDS_Proxy"
    language: str = ""
    database: str = ""
    packet_size: int = 4096
    tds_version: Tuple[int, int, int, int] = (5, 0, 0, 0)

    # Capability tokens
    capabilities: bytes = field(default_factory=bytes)

    def pack(self) -> bytes:
        """
        Pack TDS 5.0 login packet

        Login packet structure (simplified):
        - Fixed header with lengths and offsets
        - Variable length fields
        - Capability tokens
        """
        # Encode strings
        hostname_bytes = self._encode_string(self.hostname, 30)
        username_bytes = self._encode_string(self.username, 30)
        password_bytes = self._encode_string(self.password, 30)
        appname_bytes = self._encode_string(self.appname, 30)
        servername_bytes = self._encode_string(self.servername, 30)
        library_bytes = self._encode_string(self.library, 10)
        language_bytes = self._encode_string(self.language, 30)
        database_bytes = self._encode_string(self.database, 30)

        # Build login record
        login_record = bytearray()

        # Hostname (30 bytes + 1 length)
        login_record.extend(hostname_bytes)
        login_record.append(len(self.hostname))

        # Username (30 bytes + 1 length)
        login_record.extend(username_bytes)
        login_record.append(len(self.username))

        # Password (30 bytes + 1 length)
        login_record.extend(password_bytes)
        login_record.append(len(self.password))

        # Host process ID (30 bytes + 1 length)
        hostproc = b'00000000' + b'\x00' * 22
        login_record.extend(hostproc)
        login_record.append(8)

        # Type flags
        login_record.extend(bytes([
            0x03,  # Int2 byte order (little endian)
            0x01,  # Int4 byte order (little endian)
            0x06,  # Char byte order (ASCII)
            0x0A,  # Float type (IEEE 754)
            0x09,  # Date type
            0x01,  # Notify on lang change
            0x00,  # Security label hierarchy
            0x00,  # Security flags
            0x00,  # Security spare
            0x00,  # Security login role
        ]))

        # Application name (30 bytes + 1 length)
        login_record.extend(appname_bytes)
        login_record.append(len(self.appname))

        # Server name (30 bytes + 1 length)
        login_record.extend(servername_bytes)
        login_record.append(len(self.servername))

        # Remote password (length + 253 bytes)
        login_record.append(0)  # No remote password
        login_record.extend(b'\x00' * 253)

        # TDS version
        login_record.extend(bytes(self.tds_version))

        # Library name (10 bytes + 1 length)
        login_record.extend(library_bytes)
        login_record.append(len(self.library))

        # Program version
        login_record.extend(bytes([1, 0, 0, 0]))

        # Conversion flags
        login_record.extend(bytes([
            0x00,  # Convert short
            0x0D,  # Float 4 IEEE
            0x11,  # Float 8 IEEE
            0x00,  # Use DB
        ]))

        # Language (30 bytes + 1 length)
        login_record.extend(language_bytes)
        login_record.append(len(self.language))

        # Set language notify
        login_record.append(0x01)

        # Security label length
        login_record.extend(bytes([0x00, 0x00]))

        # Security label
        login_record.extend(b'\x00' * 8)

        # Database name (30 bytes + 1 length)
        login_record.extend(database_bytes)
        login_record.append(len(self.database))

        # Attach DB file (not used)
        login_record.extend(b'\x00' * 256)

        # Add capabilities
        login_record.extend(self._build_capabilities())

        return bytes(login_record)

    def _encode_string(self, s: str, max_len: int) -> bytes:
        """Encode string with padding"""
        encoded = s.encode('utf-8')[:max_len]
        return encoded + b'\x00' * (max_len - len(encoded))

    def _build_capabilities(self) -> bytes:
        """Build TDS 5.0 capability token"""
        cap_request = bytes([
            0x01, 0x0B,  # Request capabilities, length 11
            0x4F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x0E, 0x6F
        ])
        cap_response = bytes([
            0x02, 0x0B,  # Response capabilities, length 11
            0x00, 0x00, 0x00, 0x00, 0x06, 0x48, 0x00, 0x00, 0x08, 0x06, 0x00
        ])

        return bytes([TDSToken.TDS_CAPABILITY]) + bytes([len(cap_request) + len(cap_response)]) + cap_request + cap_response

    @classmethod
    def unpack(cls, data: bytes) -> 'TDSLogin':
        """Unpack login packet from bytes"""
        login = cls()

        try:
            # Extract fixed-length fields
            offset = 0

            # Hostname
            login.hostname = data[offset:offset+30].rstrip(b'\x00').decode('utf-8', errors='ignore')
            offset += 30
            data[offset]
            offset += 1

            # Username
            login.username = data[offset:offset+30].rstrip(b'\x00').decode('utf-8', errors='ignore')
            offset += 30
            data[offset]
            offset += 1

            # Password
            login.password = data[offset:offset+30].rstrip(b'\x00').decode('utf-8', errors='ignore')
            offset += 30
            data[offset]
            offset += 1

            # Host process (30 + 1)
            offset += 31

            # Type flags (10 bytes)
            offset += 10

            # App name
            login.appname = data[offset:offset+30].rstrip(b'\x00').decode('utf-8', errors='ignore')
            offset += 31

            # Server name
            login.servername = data[offset:offset+30].rstrip(b'\x00').decode('utf-8', errors='ignore')
            offset += 31

            # Remote password field (1 + 253)
            offset += 254

            # TDS version
            if offset + 4 <= len(data):
                login.tds_version = tuple(data[offset:offset+4])
            offset += 4

            # Library name
            login.library = data[offset:offset+10].rstrip(b'\x00').decode('utf-8', errors='ignore')
            offset += 11

            # Program version (4 bytes)
            offset += 4

            # Conversion flags (4 bytes)
            offset += 4

            # Language
            login.language = data[offset:offset+30].rstrip(b'\x00').decode('utf-8', errors='ignore')
            offset += 31

            # Language notify + security
            offset += 11

            # Database
            login.database = data[offset:offset+30].rstrip(b'\x00').decode('utf-8', errors='ignore')

        except Exception as e:
            logger.warning(f"Error unpacking login: {e}")

        return login
