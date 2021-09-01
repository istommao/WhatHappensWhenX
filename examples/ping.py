"""
ICMP ping

code ping3 https://github.com/kyan001/ping3/blob/master/ping3.py


ICMP Echo Request packets

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type(8)   |     Code(0)   |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Payload                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""
import enum

import os
import platform
import socket
import struct
import select
import time
import threading
import zlib


class PingError(Exception):
    pass


class TimeExceeded(PingError):
    pass


class TimeToLiveExpired(TimeExceeded):
    def __init__(self, message="Time exceeded: Time To Live expired."):
        super().__init__(message)


class DestinationUnreachable(PingError):
    pass


class DestinationHostUnreachable(DestinationUnreachable):
    def __init__(self, dest_addr=None):
        message = "Destination unreachable: Host unreachable."
        if dest_addr:
            message += " (Host='{}')".format(dest_addr)
        super().__init__(message)


class HostUnknown(PingError):
    def __init__(self, dest_addr=None):
        message = "Cannot resolve: Unknown host."
        if dest_addr:
            message += " (Host='{}')".format(dest_addr)
        super().__init__(message)


class Timeout(PingError):
    def __init__(self, timeout=None):
        message = "Request timeout for ICMP packet."
        if timeout is not None:
            message += " (Timeout={}s)".format(timeout)
        super().__init__(message)


ICMP_DEFAULT_CODE = 0  # the code for ECHO_REPLY and ECHO_REQUEST


class IcmpType(enum.IntEnum):
    """Enum for Type in ICMP Header."""
    ECHO_REPLY = 0
    DESTINATION_UNREACHABLE = 3
    REDIRECT_MESSAGE = 5
    ECHO_REQUEST = 8
    ROUTER_ADVERTISEMENT = 9
    ROUTER_SOLICITATION = 10
    TIME_EXCEEDED = 11
    BAD_IP_HEADER = 12
    TIMESTAMP = 13
    TIMESTAMP_REPLY = 14


IP_HEADER_FORMAT = "!BBHHHBBHII"
ICMP_HEADER_FORMAT = "!BBHHH"  # According to netinet/ip_icmp.h. !=network byte order(big-endian), B=unsigned char, H=unsigned short
ICMP_TIME_FORMAT = "!d"  # d=double
SOCKET_SO_BINDTODEVICE = 25  # socket.SO_BINDTODEVICE


def read_icmp_header(raw: bytes) -> dict:
    """Get information from raw ICMP header data.
    Args:
        raw: Bytes. Raw data of ICMP header.
    Returns:
        A map contains the infos from the raw header.
    """
    icmp_header_keys = ('type', 'code', 'checksum', 'id', 'seq')
    return dict(zip(icmp_header_keys, struct.unpack(ICMP_HEADER_FORMAT, raw)))


def read_ip_header(raw: bytes) -> dict:
    """Get information from raw IP header data.
    Args:
        raw: Bytes. Raw data of IP header.
    Returns:
        A map contains the infos from the raw header.
    """
    def stringify_ip(ip: int) -> str:
        return ".".join(str(ip >> offset & 0xff) for offset in (24, 16, 8, 0))  # str(ipaddress.ip_address(ip))

    ip_header_keys = ('version', 'tos', 'len', 'id', 'flags', 'ttl', 'protocol', 'checksum', 'src_addr', 'dest_addr')
    ip_header = dict(zip(ip_header_keys, struct.unpack(IP_HEADER_FORMAT, raw)))
    ip_header['src_addr'] = stringify_ip(ip_header['src_addr'])
    ip_header['dest_addr'] = stringify_ip(ip_header['dest_addr'])
    return ip_header


def checksum(source: bytes) -> int:
    """Calculates the checksum of the input bytes.

    RFC1071: https://tools.ietf.org/html/rfc1071
    RFC792: https://tools.ietf.org/html/rfc792
    Args:
        source: Bytes. The input to be calculated.
    Returns:
        int: Calculated checksum.
    """
    BITS = 16  # 16-bit long
    carry = 1 << BITS  # 0x10000

    # Even bytes (odd indexes) shift 1 byte to the left.
    result = sum(source[::2]) + (sum(source[1::2]) << (BITS // 2))

    while result >= carry:  # Ones' complement sum.
        result = sum(divmod(result, carry))  # Each carry add to right most bit.

    return ~result & ((1 << BITS) - 1)  # Ensure 16-bit


def send_package(sock: socket, dest_addr: str, icmp_id: int, seq: int, size: int):
    """Sends one ping to the given destination.

    ICMP Header (bits): type (8), code (8), checksum (16), id (16), sequence (16)
    ICMP Payload: time (double), data
    ICMP Wikipedia: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    Args:
        sock: Socket.
        dest_addr: The destination address, can be an IP address or a domain name. Ex. "192.168.1.1"/"example.com"
        icmp_id: ICMP packet id. Calculated from Process ID and Thread ID.
        seq: ICMP packet sequence, usually increases from 0 in the same process.
        size: The ICMP packet payload size in bytes. Note this is only for the payload part.
    """

    dest_addr = socket.gethostbyname(dest_addr)  # Domain name will translated into IP address, and IP address leaves unchanged.
    pseudo_checksum = 0  # Pseudo checksum is used to calculate the real checksum.

    icmp_header = struct.pack(ICMP_HEADER_FORMAT, IcmpType.ECHO_REQUEST, ICMP_DEFAULT_CODE, pseudo_checksum, icmp_id, seq)
    padding = (size - struct.calcsize(ICMP_TIME_FORMAT)) * "X"  # Using double to store current time.

    icmp_payload = struct.pack(ICMP_TIME_FORMAT, time.time()) + padding.encode()

    real_checksum = checksum(icmp_header + icmp_payload)  # Calculates the checksum on the dummy header and the icmp_payload.

    icmp_header = struct.pack(ICMP_HEADER_FORMAT, IcmpType.ECHO_REQUEST, ICMP_DEFAULT_CODE, socket.htons(real_checksum), icmp_id, seq)  # Put real checksum into ICMP header.

    packet = icmp_header + icmp_payload
    sock.sendto(packet, (dest_addr, 0))  # addr = (ip, port). Port is 0 respectively the OS default behavior will be used.


def receive_package(sock: socket, icmp_id: int, seq: int, timeout: int) -> float:
    """Receives the ping from the socket.

    IP Header (bits): version (8), type of service (8), length (16), id (16), flags (16), time to live (8), protocol (8), checksum (16), source ip (32), destination ip (32).
    ICMP Packet (bytes): IP Header (20), ICMP Header (8), ICMP Payload (*).
    Ping Wikipedia: https://en.wikipedia.org/wiki/Ping_(networking_utility)
    ToS (Type of Service) in IP header for ICMP is 0. Protocol in IP header for ICMP is 1.
    Args:
        sock: The same socket used for send the ping.
        icmp_id: ICMP packet id. Sent packet id should be identical with received packet id.
        seq: ICMP packet sequence. Sent packet sequence should be identical with received packet sequence.
        timeout: Timeout in seconds.
    Returns:
        The delay in seconds or None on timeout.

    Raises:
        TimeToLiveExpired: If the Time-To-Live in IP Header is not large enough for destination.
        TimeExceeded: If time exceeded but Time-To-Live does not expired.
        DestinationHostUnreachable: If the destination host is unreachable.
        DestinationUnreachable: If the destination is unreachable.
    """
    has_ip_header = (os.name != 'posix') or (platform.system() == 'Darwin') or (sock.type == socket.SOCK_RAW)  # No IP Header when unprivileged on Linux.

    if has_ip_header:
        ip_header_slice = slice(0, struct.calcsize(IP_HEADER_FORMAT))  # [0:20]
        icmp_header_slice = slice(ip_header_slice.stop, ip_header_slice.stop + struct.calcsize(ICMP_HEADER_FORMAT))  # [20:28]
    else:
        print("Unprivileged on Linux")
        icmp_header_slice = slice(0, struct.calcsize(ICMP_HEADER_FORMAT))  # [0:8]

    timeout_time = time.time() + timeout  # Exactly time when timeout.

    while True:
        timeout_left = timeout_time - time.time()  # How many seconds left until timeout.
        timeout_left = timeout_left if timeout_left > 0 else 0  # Timeout must be non-negative
        print("Timeout left: {:.2f}s".format(timeout_left))
        selected = select.select([sock, ], [], [], timeout_left)  # Wait until sock is ready to read or time is out.
        if selected[0] == []:  # Timeout
            raise Timeout(timeout)

        time_recv = time.time()
        print("Received time: {} ({}))".format(time.ctime(time_recv), time_recv))
        recv_data, addr = sock.recvfrom(1500)  # Single packet size limit is 65535 bytes, but usually the network packet limit is 1500 bytes.

        if has_ip_header:
            ip_header_raw = recv_data[ip_header_slice]
            ip_header = read_ip_header(ip_header_raw)
            print("Received IP header:", ip_header)

        icmp_header_raw, icmp_payload_raw = recv_data[icmp_header_slice], recv_data[icmp_header_slice.stop:]
        icmp_header = read_icmp_header(icmp_header_raw)

        print("Received ICMP header:", icmp_header)
        print("Received ICMP payload:", icmp_payload_raw)

        if not has_ip_header:  # When unprivileged on Linux, ICMP ID is rewrited by kernel.
            icmp_id = sock.getsockname()[1]  # According to https://stackoverflow.com/a/14023878/4528364
        if icmp_header['id'] and icmp_header['id'] != icmp_id:  # ECHO_REPLY should match the ID field.
            print("ICMP ID dismatch. Packet filtered out.")
            continue
        if icmp_header['type'] == IcmpType.TIME_EXCEEDED:  # TIME_EXCEEDED has no icmp_id and icmp_seq. Usually they are 0.
            if icmp_header['code'] == IcmpTimeExceededCode.TTL_EXPIRED:
                raise TimeToLiveExpired()  # Some router does not report TTL expired and then timeout shows.
            raise TimeExceeded()
        if icmp_header['type'] == IcmpType.DESTINATION_UNREACHABLE:  # DESTINATION_UNREACHABLE has no icmp_id and icmp_seq. Usually they are 0.
            if icmp_header['code'] == IcmpDestinationUnreachableCode.DESTINATION_HOST_UNREACHABLE:
                raise DestinationHostUnreachable()
            raise DestinationUnreachable()
        if icmp_header['id'] and icmp_header['seq'] == seq:  # ECHO_REPLY should match the SEQ field.
            if icmp_header['type'] == IcmpType.ECHO_REQUEST:  # filters out the ECHO_REQUEST itself.
                print("ECHO_REQUEST received. Packet filtered out.")
                continue
            if icmp_header['type'] == IcmpType.ECHO_REPLY:
                time_sent = struct.unpack(ICMP_TIME_FORMAT, icmp_payload_raw[0:struct.calcsize(ICMP_TIME_FORMAT)])[0]
                print("Received sent time: {} ({})".format(time.ctime(time_sent), time_sent))
                return time_recv - time_sent


def ping(dest_addr: str, timeout: int, src_addr: str = None, ttl: int = None, seq: int = 0, size: int = 56):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)

    print(sock)

    thread_id = threading.currentThread().ident
    process_id = os.getpid()  # If ping() run under different process, thread_id may be identical.
    icmp_id = zlib.crc32("{}{}".format(process_id, thread_id).encode()) & 0xffff  # to avoid icmp_id collision.

    send_package(sock=sock,  dest_addr=dest_addr, icmp_id=icmp_id, seq=seq, size=size)

    delay = receive_package(sock=sock, icmp_id=icmp_id, seq=seq, timeout=timeout)  # in seconds

    print('Delay: {} ms'.format(delay * 1000))


def main(dest_addr: str, timeout: int, src_addr: str = None):
    ping(dest_addr, timeout, src_addr=src_addr)


if __name__ == '__main__':
    dest_addr = 'www.baidu.com'
    timeout = 5
    src_addr = None

    main(dest_addr, timeout, src_addr=src_addr)
