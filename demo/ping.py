"""
ICMP ping

code ping3 https://github.com/kyan001/ping3/blob/master/ping3.py
"""

# # ICMP Echo Request packets
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Type(8)   |     Code(0)   |          Checksum             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           Identifier          |        Sequence Number        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                             Payload                           |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# """

import os
import time
import errno
import platform
import zlib
import struct
import socket
import threading

IP_HEADER_FORMAT = "!BBHHHBBHII"

ICMP_HEADER_FORMAT = "!BBHHH" 
ICMP_TIME_FORMAT = "!d"


def get_icmp_checksum(data):
    """Get icmp data checksum

    - https://tools.ietf.org/html/rfc1071
    - https://tools.ietf.org/html/rfc792
    """

    BITS = 16  # 16-bit long
    carry = 1 << BITS  # 0x10000

    result = sum(data[::2]) + (sum(data[1::2]) << (BITS // 2))  # Even bytes (odd indexes) shift 1 byte to the left.

    while result >= carry:  # Ones' complement sum.
        result = sum(divmod(result, carry))  # Each carry add to right most bit.

    return ~result & ((1 << BITS) - 1)  # Ensure 16-bit


def send_icmp_package(sock, icmp_id, seq, size):
    """send icmp package

    :icmp_id: Identifier
    :seq: Seq number
    """
    ECHO_REQUEST_TYPE = 8
    # the code for ECHO_REPLY and ECHO_REQUEST
    ICMP_DEFAULT_CODE = 0
    pseudo_checksum = 0

    icmp_header = struct.pack(
        ICMP_HEADER_FORMAT,
        ECHO_REQUEST_TYPE,
        ICMP_DEFAULT_CODE,
        pseudo_checksum,
        icmp_id,
        seq
    )

    padding = (size - struct.calcsize('!d')) * "X"

    send_time = time.time()
    icmp_payload = struct.pack('!d', send_time) + padding.encode()
    real_checksum = get_icmp_checksum(icmp_header + icmp_payload) 

    icmp_header = struct.pack(
        ICMP_HEADER_FORMAT,
        ECHO_REQUEST_TYPE,
        ICMP_DEFAULT_CODE,
        socket.htons(real_checksum),
        icmp_id,
        seq
    )


    dest_addr  = 'www.baidu.com'
    dest_addr = socket.gethostbyname(dest_addr)

    packet = icmp_header + icmp_payload

    sock.sendto(packet, (dest_addr, 0))


def read_icmp_header(raw):
    icmp_header_keys = ('type', 'code', 'checksum', 'id', 'seq')
    return dict(zip(icmp_header_keys, struct.unpack(ICMP_HEADER_FORMAT, raw)))


def read_ip_header(raw):
    def stringify_ip(ip: int) -> str:
        return ".".join(str(ip >> offset & 0xff) for offset in (24, 16, 8, 0))  # str(ipaddress.ip_address(ip))

    ip_header_keys = ('version', 'tos', 'len', 'id', 'flags', 'ttl', 'protocol', 'checksum', 'src_addr', 'dest_addr')
    ip_header = dict(zip(ip_header_keys, struct.unpack(IP_HEADER_FORMAT, raw)))
    ip_header['src_addr'] = stringify_ip(ip_header['src_addr'])
    ip_header['dest_addr'] = stringify_ip(ip_header['dest_addr'])
    return ip_header


def get_icmp_reply(sock, icmp_id, seq, timeout):
    has_ip_header = (os.name != 'posix') or (platform.system() == 'Darwin') or (sock.type == socket.SOCK_RAW)  # No IP Header when unprivileged on Linux.

    if has_ip_header:
        ip_header_slice = slice(0, struct.calcsize(IP_HEADER_FORMAT))  # [0:20]
        icmp_header_slice = slice(ip_header_slice.stop, ip_header_slice.stop + struct.calcsize(ICMP_HEADER_FORMAT))  # [20:28]
    else:
        icmp_header_slice = slice(0, struct.calcsize(ICMP_HEADER_FORMAT))  # [0:8]

    while True:
        time_recv = time.time()

        recv_data, addr = sock.recvfrom(1024)
        # if has_ip_header:
        ip_header_raw = recv_data[ip_header_slice]
        ip_header = read_ip_header(ip_header_raw)

        icmp_header_raw, icmp_payload_raw = recv_data[icmp_header_slice], recv_data[icmp_header_slice.stop:]
        icmp_header = read_icmp_header(icmp_header_raw)

        icmp_payload = struct.unpack(
            ICMP_TIME_FORMAT,
            icmp_payload_raw[0:struct.calcsize(ICMP_TIME_FORMAT)]
        )

        time_sent = icmp_payload[0]
        # print(time_sent, time_recv)

        time_diff = (time_recv - time_sent) * 1000
        print(ip_header)
        print(icmp_header)

        fmtstr = '{} bytes from {}: icmp_seq={} ttl={} time={} ms'
        echostr = fmtstr.format(
            64,
            ip_header['src_addr'],
            seq,
            ip_header['ttl'],
            time_diff
        )
        print(echostr)

        return


def main():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError as err:
        if err.errno == errno.EPERM:  # [Errno 1] Operation not permitted
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        else:
            raise err

    thread_id = threading.get_native_id() if hasattr(threading, 'get_native_id') else threading.currentThread().ident  # threading.get_native_id() is supported >= python3.8.
    process_id = os.getpid()  # If ping() run under different process, thread_id may be identical.
    icmp_id = zlib.crc32('{}{}'.format(process_id, thread_id).encode()) & 0xffff  # to avoid icmp_id collision.

    size = 64
    seq = 0

    while True:
        send_icmp_package(sock, icmp_id, seq, size)
        timeout = 4
        get_icmp_reply(sock, icmp_id, seq, timeout)
        seq += 1
        time.sleep(1)


if __name__ == '__main__':
    main()
