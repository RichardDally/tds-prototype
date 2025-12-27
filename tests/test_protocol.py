"""
Tests for TDS Protocol Implementation
=====================================

Run with: pytest tests/
"""

import pytest
import struct
from tds_proxy.tds import (
    TDSHeader, TDSPacket, TDSPacketType, TDSPacketStatus,
    TDSLogin, TDSTokenBuilder, TDSTokenParser, TDSToken,
    TDSDoneStatus, hexdump
)


class TestTDSHeader:
    """Tests for TDS Header parsing and building"""
    
    def test_header_pack_unpack(self):
        """Test header round-trip"""
        header = TDSHeader(
            packet_type=TDSPacketType.TDS_QUERY,
            status=TDSPacketStatus.TDS_BUFSTAT_EOM,
            length=100,
            channel=0,
            packet_number=1,
            window=0
        )
        
        packed = header.pack()
        assert len(packed) == TDSHeader.HEADER_SIZE
        
        unpacked = TDSHeader.unpack(packed)
        assert unpacked.packet_type == header.packet_type
        assert unpacked.status == header.status
        assert unpacked.length == header.length
        assert unpacked.packet_number == header.packet_number
    
    def test_header_unpack_real_packet(self):
        """Test unpacking a real TDS header"""
        # Real login packet header
        data = bytes([0x02, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00])
        
        header = TDSHeader.unpack(data)
        assert header.packet_type == TDSPacketType.TDS_LOGIN
        assert header.status == TDSPacketStatus.TDS_BUFSTAT_EOM
        assert header.length == 512
    
    def test_header_invalid_data(self):
        """Test header unpacking with insufficient data"""
        with pytest.raises(ValueError):
            TDSHeader.unpack(bytes([0x01, 0x02]))


class TestTDSPacket:
    """Tests for TDS Packet handling"""
    
    def test_packet_create(self):
        """Test packet creation"""
        data = b"SELECT 1"
        packet = TDSPacket.create(TDSPacketType.TDS_QUERY, data)
        
        assert packet.header.packet_type == TDSPacketType.TDS_QUERY
        assert packet.header.status == TDSPacketStatus.TDS_BUFSTAT_EOM
        assert packet.header.length == TDSHeader.HEADER_SIZE + len(data)
        assert packet.data == data
    
    def test_packet_pack_unpack(self):
        """Test packet round-trip"""
        original_data = b"SELECT @@version"
        packet = TDSPacket.create(TDSPacketType.TDS_QUERY, original_data)
        
        packed = packet.pack()
        unpacked = TDSPacket.unpack(packed)
        
        assert unpacked.header.packet_type == TDSPacketType.TDS_QUERY
        assert unpacked.data == original_data


class TestTDSLogin:
    """Tests for TDS Login packet"""
    
    def test_login_pack(self):
        """Test login packet packing"""
        login = TDSLogin(
            hostname="testhost",
            username="testuser",
            password="testpass",
            appname="TestApp",
            servername="TESTSERVER",
            database="testdb"
        )
        
        packed = login.pack()
        assert isinstance(packed, bytes)
        assert len(packed) > 100  # Login packet is substantial
    
    def test_login_unpack(self):
        """Test login packet unpacking"""
        login = TDSLogin(
            hostname="myhost",
            username="myuser",
            password="secret",
            appname="DBeaver",
            database="master"
        )
        
        packed = login.pack()
        unpacked = TDSLogin.unpack(packed)
        
        assert unpacked.hostname == login.hostname
        assert unpacked.username == login.username
        assert unpacked.password == login.password
        assert unpacked.appname == login.appname
        assert unpacked.database == login.database


class TestTDSTokenBuilder:
    """Tests for TDS Token building"""
    
    def test_build_loginack(self):
        """Test LOGINACK token building"""
        token = TDSTokenBuilder.build_loginack("TestServer")
        
        assert token[0] == TDSToken.TDS_LOGINACK
        assert len(token) > 10
    
    def test_build_done(self):
        """Test DONE token building"""
        token = TDSTokenBuilder.build_done(
            status=TDSDoneStatus.TDS_DONE_FINAL,
            cur_cmd=0,
            row_count=100
        )
        
        assert token[0] == TDSToken.TDS_DONE
        assert len(token) == 9  # 1 + 2 + 2 + 4 bytes
        
        # Parse the row count
        row_count = struct.unpack('<I', token[5:9])[0]
        assert row_count == 100
    
    def test_build_error(self):
        """Test ERROR token building"""
        token = TDSTokenBuilder.build_error(
            msg_number=50000,
            state=1,
            severity=16,
            message="Test error message",
            server_name="TestServer"
        )
        
        assert token[0] == TDSToken.TDS_EED
        assert b"Test error message" in token
    
    def test_build_envchange(self):
        """Test ENVCHANGE token building"""
        token = TDSTokenBuilder.build_envchange(
            change_type=1,  # Database
            new_value="newdb",
            old_value="olddb"
        )
        
        assert token[0] == TDSToken.TDS_ENVCHANGE
        assert b"newdb" in token
        assert b"olddb" in token
    
    def test_build_capability(self):
        """Test CAPABILITY token building"""
        token = TDSTokenBuilder.build_capability()
        
        assert token[0] == TDSToken.TDS_CAPABILITY
        assert len(token) > 20


class TestTDSTokenParser:
    """Tests for TDS Token parsing"""
    
    def test_parse_done_token(self):
        """Test parsing DONE token"""
        done_token = TDSTokenBuilder.build_done(
            status=TDSDoneStatus.TDS_DONE_COUNT,
            cur_cmd=0,
            row_count=42
        )
        
        tokens = TDSTokenParser.parse_tokens(done_token)
        
        assert len(tokens) == 1
        assert tokens[0]['type'] == TDSToken.TDS_DONE
        assert tokens[0]['row_count'] == 42
    
    def test_parse_multiple_tokens(self):
        """Test parsing multiple tokens"""
        data = bytearray()
        data.extend(TDSTokenBuilder.build_envchange(1, "testdb"))
        data.extend(TDSTokenBuilder.build_loginack("TestServer"))
        data.extend(TDSTokenBuilder.build_done())
        
        tokens = TDSTokenParser.parse_tokens(bytes(data))
        
        assert len(tokens) == 3
        assert tokens[0]['type'] == TDSToken.TDS_ENVCHANGE
        assert tokens[1]['type'] == TDSToken.TDS_LOGINACK
        assert tokens[2]['type'] == TDSToken.TDS_DONE
    
    def test_parse_error_token(self):
        """Test parsing ERROR token"""
        error_token = TDSTokenBuilder.build_error(
            msg_number=12345,
            state=1,
            severity=16,
            message="Something went wrong"
        )
        
        tokens = TDSTokenParser.parse_tokens(error_token)
        
        assert len(tokens) == 1
        assert tokens[0]['type'] == TDSToken.TDS_EED
        assert 'payload' in tokens[0]


class TestHexdump:
    """Tests for hexdump utility"""
    
    def test_hexdump_basic(self):
        """Test basic hexdump output"""
        data = b"Hello, World!"
        output = hexdump(data)
        
        assert "48 65 6c 6c 6f" in output  # "Hello" in hex
        assert "Hello" in output  # ASCII representation
    
    def test_hexdump_with_prefix(self):
        """Test hexdump with prefix"""
        data = b"\x00\x01\x02\x03"
        output = hexdump(data, prefix=">> ")
        
        assert output.startswith(">> ")
    
    def test_hexdump_multiline(self):
        """Test hexdump with more than 16 bytes"""
        data = bytes(range(32))
        output = hexdump(data)
        
        lines = output.split('\n')
        assert len(lines) == 2


class TestPacketTypes:
    """Tests for packet type constants"""
    
    def test_packet_types_values(self):
        """Verify packet type values match TDS spec"""
        assert TDSPacketType.TDS_QUERY == 1
        assert TDSPacketType.TDS_LOGIN == 2
        assert TDSPacketType.TDS_RPC == 3
        assert TDSPacketType.TDS_REPLY == 4
        assert TDSPacketType.TDS_CANCEL == 6
    
    def test_token_values(self):
        """Verify token values match TDS spec"""
        assert TDSToken.TDS_DONE == 0xFD
        assert TDSToken.TDS_DONEPROC == 0xFE
        assert TDSToken.TDS_DONEINPROC == 0xFF
        assert TDSToken.TDS_ERROR == 0xAA
        assert TDSToken.TDS_LOGINACK == 0xAD


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
