"""
TDS Protocol Constants
======================

Enumerations and constants for the TDS protocol.
"""

from enum import IntEnum


class TDSPacketType(IntEnum):
    """TDS Packet Types (first byte of header)"""
    TDS_QUERY = 1           # SQL query
    TDS_LOGIN = 2           # Login packet
    TDS_RPC = 3             # Remote procedure call
    TDS_REPLY = 4           # Server response
    TDS_CANCEL = 6          # Cancel request
    TDS_BULK = 7            # Bulk insert data
    TDS_NORMAL = 15         # Normal token stream
    TDS_LOGIN7 = 16         # TDS 7.0+ login
    TDS_SSPI = 17           # SSPI authentication
    TDS_PRELOGIN = 18       # Pre-login (TDS 7.1+)


class TDSPacketStatus(IntEnum):
    """TDS Packet Status (second byte of header)"""
    TDS_BUFSTAT_NORMAL = 0x00
    TDS_BUFSTAT_EOM = 0x01          # End of message
    TDS_BUFSTAT_ATTNACK = 0x02      # Attention acknowledgment
    TDS_BUFSTAT_ATTN = 0x08         # Attention
    TDS_BUFSTAT_EVENT = 0x10        # Event notification
    TDS_BUFSTAT_SEAL = 0x20         # Sealed (encrypted)
    TDS_BUFSTAT_ENCRYPT = 0x40      # Encrypted


class TDSToken(IntEnum):
    """TDS Token Types for data stream"""
    # Fixed length tokens
    TDS_OFFSET = 0x78
    TDS_RETURNSTATUS = 0x79
    TDS_PROCID = 0x7C
    TDS_COLINFO_TOKEN = 0xA5

    # Variable length tokens
    TDS_COL_NAME = 0xA0
    TDS_COL_INFO = 0xA1
    TDS_TABNAME = 0xA4
    TDS_COLINFO = 0xA5
    TDS_OPTION_CMD = 0xA6
    TDS_COMPUTE_NAMES = 0xA7
    TDS_COMPUTE_RESULT = 0xA8
    TDS_ORDER = 0xA9
    TDS_ERROR = 0xAA
    TDS_INFO = 0xAB
    TDS_PARAM = 0xAC
    TDS_LOGINACK = 0xAD
    TDS_CONTROL = 0xAE
    TDS_ROW = 0xD1
    TDS_NBC_ROW = 0xD2          # Null bitmap compressed row
    TDS_CMP_ROW = 0xD3
    TDS_PARAMS = 0xD7
    TDS_CAPABILITY = 0xE2
    TDS_ENVCHANGE = 0xE3
    TDS_EED = 0xE5              # Extended error data
    TDS_DBRPC = 0xE6
    TDS_DYNAMIC = 0xE7
    TDS_PARAMFMT = 0xEC
    TDS_AUTH = 0xED
    TDS_RESULT = 0xEE           # Result set (TDS5)
    TDS_DONE = 0xFD
    TDS_DONEPROC = 0xFE
    TDS_DONEINPROC = 0xFF

    # TDS5 specific
    TDS5_PARAMS = 0xD7
    TDS5_PARAMFMT = 0xEC
    TDS5_PARAMFMT2 = 0x20
    TDS5_ROWFMT = 0xEE
    TDS5_ROWFMT2 = 0x61


class TDSDataType(IntEnum):
    """TDS Data Types"""
    # Fixed length types
    SYBINT1 = 0x30          # tinyint (1 byte)
    SYBINT2 = 0x34          # smallint (2 bytes)
    SYBINT4 = 0x38          # int (4 bytes)
    SYBINT8 = 0x7F          # bigint (8 bytes)
    SYBFLT4 = 0x3B          # real (4 bytes)
    SYBFLT8 = 0x3E          # float (8 bytes)
    SYBBIT = 0x32           # bit (1 byte)
    SYBMONEY4 = 0x7A        # smallmoney (4 bytes)
    SYBMONEY = 0x3C         # money (8 bytes)
    SYBDATETIME4 = 0x3A     # smalldatetime (4 bytes)
    SYBDATETIME = 0x3D      # datetime (8 bytes)

    # Variable length types
    SYBCHAR = 0x2F          # char
    SYBVARCHAR = 0x27       # varchar
    SYBBINARY = 0x2D        # binary
    SYBVARBINARY = 0x25     # varbinary
    SYBTEXT = 0x23          # text
    SYBIMAGE = 0x22         # image
    SYBNTEXT = 0x63         # ntext
    SYBNVARCHAR = 0x67      # nvarchar
    SYBNCHAR = 0x6F         # nchar

    # Nullable types
    SYBINTN = 0x26          # nullable int
    SYBFLTN = 0x6D          # nullable float
    SYBMONEYN = 0x6E        # nullable money
    SYBDATETIMN = 0x6F      # nullable datetime
    SYBBITN = 0x68          # nullable bit

    # Decimal/Numeric
    SYBDECIMAL = 0x6A
    SYBNUMERIC = 0x6C

    # Long types (TDS 5.0)
    SYBLONGCHAR = 0xAF
    SYBLONGBINARY = 0xE1


class TDSEnvChangeType(IntEnum):
    """Environment change types"""
    TDS_ENV_DATABASE = 1
    TDS_ENV_LANG = 2
    TDS_ENV_CHARSET = 3
    TDS_ENV_PACKSIZE = 4
    TDS_ENV_LCID = 5
    TDS_ENV_COLLATION = 7


class TDSDoneStatus(IntEnum):
    """DONE token status flags"""
    TDS_DONE_FINAL = 0x0000
    TDS_DONE_MORE = 0x0001
    TDS_DONE_ERROR = 0x0002
    TDS_DONE_INXACT = 0x0004
    TDS_DONE_PROC = 0x0008
    TDS_DONE_COUNT = 0x0010
    TDS_DONE_ATTN = 0x0020
    TDS_DONE_EVENT = 0x0040
    TDS_DONE_SRVERROR = 0x0100
