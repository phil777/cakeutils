#! /usr/bin/env python

import socket
import logging
import struct
import os
from select import select
#import nfqueue
import cakeutils


class InterceptorException(Exception):
    pass

log = logging.getLogger("interceptor")

SO_ORIGINAL_DST = 80 # Socket option
IP_TRANSPARENT = 19
IP_RECVORIGDSTADDR = 20
IP_PKTINFO = 8

def display(x):
    e=x.encode("string_escape")
    return "%s%s" % (e[:50], ["","..."][len(e)>50])

def dispdir(dir):
    return {1:"->",-1:"<-"}[dir]

def dispcnx(cnxid, dir):
    return "%s %s:%u%s%s:%u" % (cnxid[4], cnxid[0],cnxid[1],
                                dispdir(dir), cnxid[2],cnxid[3])

def system(cmd, canfail=False):
    log.info("Exec'ing [%s]" % cmd)
    ret = os.system(cmd)
    if ret != 0:
        err = "Error %i when executing [%s]" % (ret, cmd)
        if canfail:
            log.warning(err)
        else:
            raise InterceptorException()
    return ret


def cb_log(cnxid, dir, data):
    log.debug("%s: len=%i %s" % (dispcnx(cnxid, dir), len(data), display(data)))

def intercept(port, udp=True, tcp=True, callback = cb_log):
    
    def protected_callback(cnxid, dir, data, callback=callback):
        try:
            return callback(cnxid, dir, data)
        except Exception,e:
            log.exception("Callback exception on %s" % dispcnx(cnxid,dir))

    selsock = set()
    inttcp = set()
    intudp = set()
    connecting = set()
    tcp_pairs = {}
    udp_pairs = {}
    udp_cnx = {}
    infos = {}

    if tcp:
        log.info("Starting TCP interception on port %i", port)
        st = socket.socket()
        st.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)    
        st.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        st.bind(("", port))
        st.listen(5)
        selsock.add(st)
        
    if udp:
        log.info("Starting UDP interception on port %i", port)
        su = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        su.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
        su.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  
        su.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, 1)
        su.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        su.bind(("", port))
        selsock.add(su)

    def close_pair(s, pair):
        try:
            s.shutdown(2)
        except socket.error:
            pass
        s.close()
        t = pair[s]
        try:
            t.shutdown(2)
        except socket.error:
            pass
        t.close()
        del(pair[s])
        del(pair[t])
        del(infos[s])
        del(infos[t])

    while True:
        rcv,snd,_ = select(selsock, connecting, [])
        for sk in snd:
            connecting.remove(sk)
            cnxid,dir = infos[sk]
            try:
                sk.send("")
            except socket.error,e:
                log.info("Failed to connect %s: %s" % (dispcnx(cnxid,dir), e))
                close_pair(sk, tcp_pairs)
            else:
                sk2 = tcp_pairs[sk]
                log.info("Connected %s" % dispcnx(cnxid, dir))
                sk.setblocking(True)
                selsock.add(sk)
                selsock.add(sk2)
                inttcp.add(sk)
                inttcp.add(sk2)
        for sk in rcv:
            try:
                if sk == st:
                    t,src = st.accept()
                    sa_dst = t.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
                    dst_port,dst_ip = struct.unpack("!2xH4s8x", sa_dst)
                    dst_ip = socket.inet_ntoa(dst_ip)
                    dst = (dst_ip, dst_port)
                    cnxid = src+dst+("TCP",)
                    log.info("Intercepted TCP %s" % dispcnx(cnxid, 1))
    
                    t2 = socket.socket()
                    t2.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
                    t2.setblocking(False)
#                    t2.bind(src)
                    try:
                        t2.connect(dst)
                    except socket.error,e:
                        if e.errno != 115:
                            log.warning("Failed to connect to %s:%u: %s" (dst+(e,)))
                            continue
                    connecting.add(t2)
                    tcp_pairs[t] = t2
                    tcp_pairs[t2] = t
                    infos[t] = cnxid,1
                    infos[t2] = cnxid,-1
                elif sk == su:
                    data,src,msg = cakeutils.recvmsg(sk, bufsize=8192)
    
                    # Decode anscillary message to get original destination
                    rawdst = msg.get((socket.SOL_IP, IP_RECVORIGDSTADDR))
                    if not rawdst:
                        log.warning("Can't obtain original destination from packet %r" % data)
                        continue
                    port,ip = struct.unpack_from("!xxH4s", rawdst)
                    dst = socket.inet_ntoa(ip),port
                    cnxid = src+dst+("UDP",)
                    
    
                    if cnxid not in udp_cnx:
                        log.info("Intercepted UDP %s" % dispcnx(cnxid, 1))
    
                        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
                        t.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
                        t.bind(dst)
                        t.connect(src)
    
                        t2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        t2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
                        t2.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
#                        t2.bind(src)
                        t2.connect(dst)
                        
                        intudp.add(t)
                        intudp.add(t2)
                        infos[t] = cnxid,1
                        infos[t2] = cnxid,-1
                        selsock.add(t)
                        selsock.add(t2)
                        udp_pairs[t] = t2
                        udp_pairs[t2] = t
                        
                        udp_cnx[cnxid] = t2
                    else:
                        t2 = udp_cnx[cnxid]
    
                    d2 = protected_callback(cnxid, 1, data)
                    if d2 is not None:
                        data = d2
                    t2.send(data)
    
                elif sk in inttcp:
                    cnxid,dir = infos[sk]
                    sk2 = tcp_pairs[sk]
                    data = sk.recv(8192)
                            
                    if data == "":
                        inttcp.remove(sk)
                        inttcp.remove(sk2)
                        selsock.remove(sk)
                        selsock.remove(sk2)
                        close_pair(sk, tcp_pairs)
                        log.info("Closing TCP %s" % dispcnx(cnxid, dir))
                        continue
                    d2 = protected_callback(cnxid, dir, data)
                    if d2 is not None:
                        data = d2
                    sk2.send(data)
                elif sk in intudp:
                    cnxid,dir = infos[sk]
                    sk2 = udp_pairs[sk]
                    try:
                        data = sk.recv(8192)
                    except socket.error,e:
                        if e.errno == 111: # connection refused
                            log.info("UDP refused for %s. Closing" % dispcnx(cnxid, dir))
                            intudp.remove(sk)
                            intudp.remove(sk2)
                            selsock.remove(sk)
                            selsock.remove(sk2)
                            del(udp_cnx[cnxid])
                            close_pair(sk, udp_pairs)
                            continue
                        else:
                            raise

                    d2 = protected_callback(cnxid, dir, data)
                    if d2 is not None:
                        data = d2
                    sk2.send(data)
            except KeyboardInterrupt:
                raise
            except socket.error,e:
                log.exception("socket error: %s" % e)
            except Exception,e:
                log.exception("Unhandled exception")


        

class Configurator:
    def __init__(self, command=system):
        self.init=[]
        self.fini=[]
        self.level=0
        self.command = command

    def add_init(self, *cmds):
        self.init.append(cmds)
    def add_fini(self, *cmds):
        self.fini.append(cmds)

    def set_max_level(self):
        self.level = len(self.init)
    
    def configure(self):
        for l in self.init:
            for c in l:
                self.command(c)
            self.level+=1
    def deconfigure(self):
        while self.level:
            for c in self.fini[self.level-1]:
                self.command(c)
                self.level -= 1
            
                
        

def main(*argv, **kargs):
    callback = kargs.get("callback", cb_log)
    import optparse

    parser = optparse.OptionParser()

    parser.add_option("-p", dest="port", type="int", default=5555,
                      help="listen to tcp port PORT (default=5555)", metavar="PORT")
                 
    parser.add_option("-I", "--iface", "--interface", dest="iface", 
                      help="intercept traffic coming from IFACE", metavar="IFACE")
    parser.add_option("--filter", dest="filter", default="",
                      help="intercept only traffic matching FILTER Netfilter match rules", metavar="FILTER")
    parser.add_option("-U", dest="user", default="user",
                      help="intercept USER's connections", metavar="USER")
    parser.add_option("-C", dest="configure", action="store_true",
                      help="configure system")
    parser.add_option("-D", dest="deconfigure", action="store_true",
                      help="only configure system")

                 

    (options,args) = parser.parse_args(list(argv))

    options.tpmark = 42
    options.mark = 42
    options.tablenum = 101
    
    # configure logging
    log.setLevel(logging.DEBUG)
    console_handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(process)5i] %(levelname)-5s: %(message)s')
    console_handler.setFormatter(formatter)
    log.addHandler(console_handler)
    log.info("Starting interceptor.")

    
    if options.configure or options.deconfigure:
        cf = Configurator()
        cf.add_init("iptables -t mangle -N INTERCEPT")
        cf.add_fini("iptables -t mangle -X INTERCEPT")
        cf.add_init("iptables -t mangle -A INTERCEPT -j MARK --set-mark {0.mark}".format(options),
                    "iptables -t mangle -A INTERCEPT -j ACCEPT")
        cf.add_fini("iptables -t mangle -F INTERCEPT")
        cf.add_init("iptables -t mangle -A PREROUTING -p tcp -m socket -j INTERCEPT")
        cf.add_fini("iptables -t mangle -D PREROUTING -p tcp -m socket -j INTERCEPT")
        cf.add_init("ip rule add fwmark {0.mark} lookup {0.tablenum}".format(options))
        cf.add_fini("ip rule del fwmark {0.mark} lookup {0.tablenum}".format(options))
        cf.add_init("ip route add local 0/0 dev lo table {0.tablenum}".format(options))
        cf.add_fini("ip route del local 0/0 dev lo table {0.tablenum}".format(options))
        cf.add_init("iptables -t mangle -A PREROUTING -p udp -i {0.iface} {0.filter} -j TPROXY --on-port {0.port} --tproxy-mark {0.tpmark}".format(options))
        cf.add_fini("iptables -t mangle -D PREROUTING -p udp -i {0.iface} {0.filter} -j TPROXY --on-port {0.port} --tproxy-mark {0.tpmark}".format(options))
        cf.add_init("iptables -t mangle -A PREROUTING -p tcp -i {0.iface} {0.filter} -j TPROXY --on-port {0.port} --tproxy-mark {0.tpmark}".format(options))
        cf.add_fini("iptables -t mangle -D PREROUTING -p tcp -i {0.iface} {0.filter} -j TPROXY --on-port {0.port} --tproxy-mark {0.tpmark}".format(options))
        if options.deconfigure:
            cf.set_max_level()

    try:
        if options.configure:
            log.info("Configuring system")
            cf.configure()    
        
        intercept(options.port, callback=callback)
        
    except KeyboardInterrupt:
        log.info("Interrupted by user")

    finally:

        if options.configure or options.deconfigure:
            log.info("Deconfiguring system")
            cf.deconfigure()

    log.info("The End.")


if __name__ == "__main__":
    import sys
    main(*sys.argv[1:])
