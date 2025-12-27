"""
TDS Token Builders and Parsers
==============================

Classes for building and parsing TDS protocol tokens.
"""

import struct
import logging
from typing import List, Dict, Any

from .constants import TDSToken, TDSDoneStatus

logger = logging.getLogger(__name__)


class TDSTokenBuilder:
    """Build TDS tokens for server responses"""

    @staticmethod
    def build_loginack(server_name: str = "SAP_ASE", tds_version: tuple = (5, 0, 0, 0)) -> bytes:
        """Build LOGINACK token"""
        token = bytearray([TDSToken.TDS_LOGINACK])

        # Build payload
        payload = bytearray()
        payload.append(0x05)  # Interface type (TDS 5.0)
        payload.extend(bytes(tds_version))  # TDS version

        # Server name
        server_bytes = server_name.encode('utf-8')[:30]
        payload.append(len(server_bytes))
        payload.extend(server_bytes)

        # Program version
        payload.extend(bytes([16, 0, 0, 0]))  # ASE 16.0

        # Add length
        length = len(payload)
        token.extend(struct.pack('<H', length))
        token.extend(payload)

        return bytes(token)

    @staticmethod
    def build_done(status: int = TDSDoneStatus.TDS_DONE_FINAL,
                   cur_cmd: int = 0,
                   row_count: int = 0) -> bytes:
        """Build DONE token"""
        return struct.pack('<BHHI', TDSToken.TDS_DONE, status, cur_cmd, row_count)

    @staticmethod
    def build_envchange(change_type: int, new_value: str, old_value: str = "") -> bytes:
        """Build ENVCHANGE token"""
        token = bytearray([TDSToken.TDS_ENVCHANGE])

        payload = bytearray()
        payload.append(change_type)

        # New value
        new_bytes = new_value.encode('utf-8')
        payload.append(len(new_bytes))
        payload.extend(new_bytes)

        # Old value
        old_bytes = old_value.encode('utf-8')
        payload.append(len(old_bytes))
        payload.extend(old_bytes)

        # Add length
        token.extend(struct.pack('<H', len(payload)))
        token.extend(payload)

        return bytes(token)

    @staticmethod
    def build_error(msg_number: int,
                    state: int,
                    severity: int,
                    message: str,
                    server_name: str = "",
                    proc_name: str = "",
                    line_number: int = 0) -> bytes:
        """Build ERROR/INFO token (EED - Extended Error Data for TDS 5.0)"""
        token = bytearray([TDSToken.TDS_EED])

        payload = bytearray()

        # Message number (4 bytes)
        payload.extend(struct.pack('<I', msg_number))

        # State and severity
        payload.append(state)
        payload.append(severity)

        # TDS status
        payload.append(0)

        # Transaction state
        payload.extend(struct.pack('<H', 0))

        # Message
        msg_bytes = message.encode('utf-8')
        payload.extend(struct.pack('<H', len(msg_bytes)))
        payload.extend(msg_bytes)

        # Server name
        server_bytes = server_name.encode('utf-8')
        payload.append(len(server_bytes))
        payload.extend(server_bytes)

        # Procedure name
        proc_bytes = proc_name.encode('utf-8')
        payload.append(len(proc_bytes))
        payload.extend(proc_bytes)

        # Line number
        payload.extend(struct.pack('<H', line_number))

        # Add length
        token.extend(struct.pack('<H', len(payload)))
        token.extend(payload)

        return bytes(token)

    @staticmethod
    def build_info(msg_number: int, message: str, server_name: str = "") -> bytes:
        """Build INFO message"""
        return TDSTokenBuilder.build_error(
            msg_number=msg_number,
            state=1,
            severity=10,  # INFO level
            message=message,
            server_name=server_name
        )

    @staticmethod
    def build_capability() -> bytes:
        """Build CAPABILITY token for TDS 5.0"""
        token = bytearray([TDSToken.TDS_CAPABILITY])

        # Request capabilities
        cap_request = bytes([
            0x01, 0x0E,  # Type 1 (request), length 14
            0x07, 0x4F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0x0E, 0x6F, 0x00, 0x00
        ])

        # Response capabilities
        cap_response = bytes([
            0x02, 0x0E,  # Type 2 (response), length 14
            0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x48, 0x00,
            0x00, 0x08, 0x06, 0x00, 0x00, 0x00
        ])

        payload = cap_request + cap_response
        token.extend(struct.pack('<H', len(payload)))
        token.extend(payload)

        return bytes(token)


class TDSTokenParser:
    """Parse TDS tokens from server responses"""

    @staticmethod
    def parse_tokens(data: bytes) -> List[Dict[str, Any]]:
        """Parse all tokens from a TDS data stream"""
        tokens = []
        offset = 0

        while offset < len(data):
            try:
                token_type = data[offset]
                offset += 1

                token_info = {'type': token_type, 'type_name': TDSTokenParser._get_token_name(token_type)}

                # Handle different token types
                if token_type in (TDSToken.TDS_DONE, TDSToken.TDS_DONEPROC, TDSToken.TDS_DONEINPROC):
                    if offset + 7 <= len(data):
                        status, cur_cmd, row_count = struct.unpack('<HHI', data[offset:offset+8])
                        offset += 8
                        token_info.update({
                            'status': status,
                            'cur_cmd': cur_cmd,
                            'row_count': row_count
                        })

                elif token_type in (TDSToken.TDS_ERROR, TDSToken.TDS_INFO, TDSToken.TDS_EED):
                    if offset + 2 <= len(data):
                        length = struct.unpack('<H', data[offset:offset+2])[0]
                        offset += 2
                        payload = data[offset:offset+length]
                        offset += length
                        token_info['payload'] = payload
                        token_info['length'] = length

                elif token_type == TDSToken.TDS_ENVCHANGE:
                    if offset + 2 <= len(data):
                        length = struct.unpack('<H', data[offset:offset+2])[0]
                        offset += 2
                        payload = data[offset:offset+length]
                        offset += length

                        if len(payload) > 0:
                            token_info['change_type'] = payload[0]
                        token_info['payload'] = payload

                elif token_type == TDSToken.TDS_LOGINACK:
                    if offset + 2 <= len(data):
                        length = struct.unpack('<H', data[offset:offset+2])[0]
                        offset += 2
                        payload = data[offset:offset+length]
                        offset += length
                        token_info['payload'] = payload

                elif token_type == TDSToken.TDS_CAPABILITY:
                    if offset + 2 <= len(data):
                        length = struct.unpack('<H', data[offset:offset+2])[0]
                        offset += 2
                        payload = data[offset:offset+length]
                        offset += length
                        token_info['capabilities'] = payload

                elif token_type in (TDSToken.TDS_RESULT, TDSToken.TDS5_ROWFMT, TDSToken.TDS5_ROWFMT2):
                    if offset + 2 <= len(data):
                        length = struct.unpack('<H', data[offset:offset+2])[0]
                        offset += 2
                        payload = data[offset:offset+length]
                        offset += length
                        token_info['columns'] = payload

                elif token_type == TDSToken.TDS_ROW:
                    # Row data - variable length, need column info to parse
                    token_info['raw_offset'] = offset
                    # Skip to next recognizable token
                    while offset < len(data) and data[offset] not in (
                        TDSToken.TDS_DONE, TDSToken.TDS_ROW, TDSToken.TDS_ERROR
                    ):
                        offset += 1

                else:
                    # Unknown token - try to read length and skip
                    if offset + 2 <= len(data):
                        try:
                            length = struct.unpack('<H', data[offset:offset+2])[0]
                            if length < len(data) - offset:
                                offset += 2 + length
                            else:
                                break
                        except struct.error:
                            break
                    else:
                        break

                tokens.append(token_info)

            except Exception as e:
                logger.warning(f"Error parsing token at offset {offset}: {e}")
                break

        return tokens

    @staticmethod
    def _get_token_name(token_type: int) -> str:
        """Get human-readable token name"""
        try:
            return TDSToken(token_type).name
        except ValueError:
            return f"UNKNOWN_0x{token_type:02X}"
