

# # what happens when ping
# import struct
# import socket

# ICMP_CODE = socket.getprotobyname('icmp')


# def get_checksum(data):
#     check_sum = 0
#     count_to = (len(source_string) / 2) * 2
#     count = 0

#     while count < count_to:
#         this_val = ord(source_string[count + 1])*256+ord(source_string[count])
#         check_sum = check_sum + this_val
#         check_sum = check_sum & 0xffffffff # Necessary?
#         count = count + 2

#     if count_to < len(source_string):
#         check_sum = check_sum + ord(source_string[len(source_string) - 1])
#         check_sum = check_sum & 0xffffffff # Necessary?

#     check_sum = (check_sum >> 16) + (check_sum & 0xffff)
#     check_sum = check_sum + (check_sum >> 16)

#     answer = ~check_sum
#     answer = answer & 0xffff

#     answer = answer >> 8 | (answer << 8 & 0xff00)
#     return answer


# def create_icmp_packet(uid):
#     ICMP_ECHO_REQUEST = 8

#     header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, uid, 1)
#     data = 192 * 'X'

#     checksum = get_checksum(header + data)

#     header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0,
#                          socket.htons(checksum), uid, 1)
#     return header + data


# def main():

# if __name__ == '__main__':
#     main()
