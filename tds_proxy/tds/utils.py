"""
TDS Utility Functions
=====================

Helper functions and utilities for TDS protocol handling.
"""


class TDSQueryBuilder:
    """Build TDS query packets"""

    @staticmethod
    def build_query(sql: str) -> bytes:
        """Build a TDS language/query packet"""
        # For TDS 5.0, queries are sent as raw SQL text
        return sql.encode('utf-8')

    @staticmethod
    def build_cancel() -> bytes:
        """Build a cancel request"""
        return b''  # Cancel is just the header with no payload


def hexdump(data: bytes, prefix: str = "") -> str:
    """Create hex dump of data for debugging"""
    lines = []
    for i in range(0, len(data), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        lines.append(f"{prefix}{i:04x}  {hex_part:<48}  {ascii_part}")
    return '\n'.join(lines)
