#! /usr/bin/env python

## This file is part of cakeutils
## See http://www.secdev.org/projects/cakeutils for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license


# This file contains man-in-the-middle class to use with netfilter REDIRECT target

import socket
import select
import struct
import logging
import cakeutils.netfilter

log = logging.getLogger("cakeutils")

class NF_REDIRECT_MITM:
    def __init__(self, port, action):
        self.action = action
        self.port = port
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("",port))
        s.listen(5)
        self.s = s


    def run(self):
        cin = []
        cout = []
        cnxdb = {}
        c2s = {}
        s2c = {}

        log.info("Running on port %i" % self.port)
        while True:
            log.debug("cin=%r cout=%r" % ([cnxdb[x][0]+"->"+cnxdb[x][2] for x in cin],
                                          [cnxdb[x][0]+"->"+cnxdb[x][2] for x in cout]))
            selin,selout,selrr = select.select([self.s]+cin+cout, [],[])
            for fd in selin:
                if fd == self.s:
                    csock,clt = self.s.accept()
                    srv = cakeutils.netfilter.get_original_dst(csock)
                    ssock = socket.socket()
                    try:
                        ssock.connect(srv)
                    except socket.error,e:
                        log.info("Could not connect to %s:%i: %s" % (srv[0],srv[1],e))
                        continue

                    cin.append(csock)
                    cout.append(ssock)
                    cnxdb[ssock] = srv+clt
                    cnxdb[csock] = clt+srv
                    c2s[csock] = ssock
                    s2c[ssock] = csock

                    self.action.open_cnx(clt+srv, csock, ssock)

                else:
                    if fd in cin:
                        csock = fd
                        ssock = c2s[csock]
                        data_hook = self.action.data_from_client
                    elif fd in cout:
                        ssock = fd
                        csock = s2c[ssock]
                        data_hook = self.action.data_from_server
                    else:
                        log.error("??? unexpected fd returned from select")
                        continue

                    data = fd.recv(1600)

                    log.debug(">>> [%s:%i -> %s:%i] Got pkt (%i bytes)" % (cnxdb[fd]+(len(data),)))


                    if data:
                        data_hook(cnxdb[csock], csock, ssock, data)
                    else:
                        log.debug(">>> [%s:%i -> %s:%i] Closed" % cnxdb[fd])
                        self.action.close_cnx(cnxdb[csock], csock, ssock)
                        del(cnxdb[csock])
                        del(cnxdb[ssock])
                        cin.remove(csock)
                        cout.remove(ssock)
                        csock.close()
                        ssock.close()

class MITM_action:
    def __init__(self):
        pass
    def open_cnx(self, cnx, csock, ssock):
        pass
    def close_cnx(self, cnx, csock, ssock):
        pass
    def data_from_client(self, data, cnx, csock, ssock):
        pass
    def data_from_server(self, data, cnx, csock, ssock):
        pass


class PassThrough(MITM_action):
    def data_from_client(self, data, cnx, csock, ssock):
        ssock.send(data)        
    def data_from_server(self, data, cnx, csock, ssock):
        csock.send(data)
        

class DumpTraffic(PassThrough):
    def __init__(self, dumpdir="", fname_format="%s:%i-%s:%i", buffering=0):
        self.flist = {}
        self.dumpdir = dumpdir
        self.fname_format = fname_format
        self.buffering = buffering

    def open_cnx(self, cnx, csock, ssock):
        fn = self.fname_format % cnx
        fc = open(os.path.join(self.dumpdir, fn+".client"), "w", self.buffering)
        fs = open(os.path.join(self.dumpdir, fn+".server"), "w", self.buffering)
        self.flist[cnx] = fc,fs

    def close_cnx(self, cnx, csock, ssock):
        fc,fs = self.flist[cnx]
        fc.close()
        fs.close()
        del(self.flist[cnx])

    def data_from_client(self, cnx, csock, ssock, data):
        fc,fs = self.flist[cnx]
        fc.write(data)
        PassThrough.data_from_client(cnx, csock, ssock, data)

    def data_from_server(self, cnx, csock, ssock, data):
        fc,fs = self.flist[cnx]
        fs.write(data)
        PassThrough.data_from_server(cnx, csock, ssock, data)


class MonoStreamDispatcher(MITM_action):
    def __init__(self, client_stream_manager, server_stream_manager):
        MITM_action.__init__(self)
        self.cmgr = client_stream_manager
        self.smgr = server_stream_manager
        self.cmgrs = {}
        self.smgrs = {}
    def open_cnx(self, cnx, csock, ssock):
        self.cmgrs[cnx] = self.cmgr(cnx,csock,ssock)
        self.smgrs[cnx] = self.smgr(cnx,csock,ssock)
    def close_cnx(self, cnx, csock, ssock):
        del(self.cmgrs[cnx])
        del(self.smgrs[cnx])
    def data_from_client(self, cnx, csock, ssock, data):
        self.cmgrs[cnx].data_from_client(data)
    def data_from_server(self, cnx, csock, ssock, data):
        self.smgrs[cnx].data_from_server(data)

class StreamDispatcher(MITM_action):
    def __init__(self, stream_manager):
        MITM_action.__init__(self)
        self.mgr = stream_manager
        self.mgrs = {}
    def open_cnx(self, cnx, csock, ssock):
        self.mgrs[cnx] = self.mgr(cnx,csock,ssock)
    def close_cnx(self, cnx, csock, ssock):
        del(self.mgrs[cnx])
    def data_from_client(self, cnx, csock, ssock, data):
        self.mgrs[cnx].data_from_client(data)
    def data_from_server(self, cnx, csock, ssock, data):
        self.mgrs[cnx].data_from_server(data)

