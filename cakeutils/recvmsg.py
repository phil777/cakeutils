#! /usr/bin/env python



from ctypes import c_uint,c_int,POINTER,c_void_p,create_string_buffer,string_at,Structure,cdll,cast,pointer,sizeof,byref,c_short,c_ushort,c_uint32,c_byte
import struct,socket

# 32bits only
c_size_t = c_uint
c_ssize_t = c_int
c_socklen_t = c_uint


class c_iovec(Structure):
    _fields_ = (
        ("base", c_void_p),
        ("len", c_size_t),
        )

c_iovec_p = POINTER(c_iovec)

class c_msghdr(Structure):
    _fields_ = (
        ("name", c_void_p),
        ("namelen", c_socklen_t),
        ("iov", c_iovec_p),
        ("iovlen", c_size_t),
        ("control", c_void_p),
        ("controllen", c_socklen_t),
        ("flags", c_int)
        )

c_msghdr_p = POINTER(c_msghdr)

class c_cmsghdr(Structure):
    _fields_ = (
        ("len", c_socklen_t),
        ("level", c_int),
        ("type", c_int),
        ("data", c_byte*0)
        )

c_cmsghdr_p = POINTER(c_cmsghdr)

class c_sockaddr_in(Structure):
    _fields_ = (
        ("family", c_short),
        ("port", c_ushort),
        ("addr", c_byte*4),
        ("zero", c_byte*8),
)

libc = cdll.LoadLibrary("libc.so.6")

libc.recvmsg.argtypes = [c_int, c_msghdr_p , c_int]
libc.recvmsg.restype = c_ssize_t

def recvmsg(sock, flags=0, bufsize=1024):
    sockfd = sock.fileno()
    
    buf = create_string_buffer(bufsize)
    ctrlbuf = create_string_buffer(1024)
    
    sin = c_sockaddr_in()
    iov = c_iovec(base = cast(buf, c_void_p), 
                  len = bufsize)
    msg = c_msghdr(name = cast(pointer(sin), c_void_p),
                   namelen = sizeof(sin),
                   iov = pointer(iov),
                   iovlen = 1,
                   control = cast(ctrlbuf, c_void_p),
                   controllen = sizeof(ctrlbuf),
                   )

    ret = libc.recvmsg(sockfd, byref(msg), flags)
    if ret == -1:
        raise Exception("recvmsg error (%i)" % get_errno())
        
    data = string_at(iov.base, ret)
    
    from_ = socket.inet_ntoa(sin.addr), socket.ntohs(sin.port)

    ctrl = string_at(msg.control, msg.controllen)

    ofs = 0
    
    messages = {}
    fmt = "III"
    fmtsz = struct.calcsize(fmt)
    while ofs < len(ctrl):
        l,lvl,typ = struct.unpack_from(fmt, ctrl, ofs)
        messages[lvl,typ] = ctrl[ofs+fmtsz:ofs+l]
        ofs += l

    return data, from_, messages



if __name__ == "__main__":
    from socket import *
    SO_TIMESTAMP = 29
    IP_RECVORIGDSTADDR = 20
    s = socket(AF_INET, SOCK_DGRAM)
    s.setsockopt(SOL_SOCKET, SO_TIMESTAMP, 1)
    s.setsockopt(SOL_IP, IP_RECVORIGDSTADDR, 1)
    s.bind(("",4444))
    while True:
        print("recv %r" % (recvmsg(s),))
