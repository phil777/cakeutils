


import struct,socket

SO_ORIGINAL_DST = 80


def get_original_dst(fd):
    sockaddr_in = fd.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port,ip = struct.unpack("!2xH4s8x", sockaddr_in)
    ip = socket.inet_ntoa(ip)
    return ip,port
