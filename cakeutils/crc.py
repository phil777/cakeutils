


class _CRC_metaclass(type):
    @staticmethod
    def _precalc_table_reflect(crcpoly, sz):
        t = []
        for i in xrange(256):
            crc = i
            for j in range(8):
                b0 = crc & 1
                crc >>= 1
                if b0:
                    crc ^= crcpoly
            t.append(crc)
        return t
    @staticmethod
    def _precalc_table(crcpoly, sz):
        t = []
        hbmsk = (1<<(sz-1))
        msk = (1<<sz)-1
        for i in xrange(256):
            crc = i<<(sz-8)
            for j in range(8):
                bsz = crc & hbmsk
                crc <<= 1
                if bsz:
                    crc ^= crcpoly
            t.append(crc&msk)
        return t
    @staticmethod
    def _rev_num(x, sz):
        y=0
        for i in range(sz):
            y <<= 1
            y |= x&1
            x >>= 1
        return y

    def __new__(cls, name, bases, dct):
        newcls = super(_CRC_metaclass, cls).__new__(cls, name, bases, dct)
        if not newcls.name:
            newcls.name = newcls.__name__
        if bases: # exclude parent class because it is virtual
            if newcls.reflect_input:
                newcls.table = cls._precalc_table_reflect(cls._rev_num(newcls.poly, 
                                                                       newcls.size),
                                                          newcls.size)
            else:
                newcls.table = cls._precalc_table(newcls.poly,newcls.size)
            newcls.list.append(newcls)
        newcls.mask=(1<<newcls.size)-1
        return newcls
        
    def __call__(self, msg):
        crc = self.init
        msg = self.header+msg+self.trailer
        if self.reflect_input:
            for c in msg:
                idx = (crc&0xff) ^ ord(c)
                crc >>= 8
                crc ^= self.table[idx]
        else:
            for c in msg:
                idx = (crc>>(self.size-8)) ^ ord(c)
                crc <<= 8
                crc &= self.mask
                crc ^= self.table[idx]
        crc = (crc^self.xor)&self.mask
        if self.reflect_input^self.reflect_output:
            crc = self._rev_num(crc, self.size)
        return crc
    def __repr__(self):
        return ("<%s size=%i poly=%x init=%x xor=%x reflect_input=%x reflect_output=%x>" % (self.name,
                self.size, self.poly, self.init, self.xor, self.reflect_input, self.reflect_output))
    def python(self):
        print ('class %(name)s(CRC):\n'
               +'\tname="%(name)s"'
               +'\n\tpoly=%(poly)#x'
               +'\n\tsize=%(size)i'
               +'\n\tinit=%(init)#x'
               +'\n\txor=%(xor)#x'
               +'\n\treflect_input=%(reflect_input)r'
               +'\n\treflect_output=%(reflect_output)r') % self.__dict__


class CRC:
    __metaclass__ = _CRC_metaclass
    name = ""
    list = []
    size = 0
    poly = 0
    init = 0
    xor = 0
    reflect_input = False
    reflect_output = False
    header = ""
    trailer = ""
    test_vector = None
    @classmethod
    def create(cls,**args):
        name = args["name"]
        return _CRC_metaclass.__new__(_CRC_metaclass, name, (cls,), args)
    @classmethod
    def find_params(cls, msg, target, size, poly=None):
        if size == 16:
            targets = [(target >> 8) | ((target&0xff) << 8)]
        elif size == 32:
            targets = [(target >>24)| (target >> 16)&0xff | (target >> 8)&0xff | target &0xff]
        else:
            targets = []
        targets.append(target)
        if poly is None:
            if size == 16:
                poly = set([0x1021])
            elif size== 32:
                poly = set([0x4c11db7])
        else:
            poly = set([poly])
        for p in poly.copy():
            poly.add(cls._rev_num(p,size))
        res = []
        for init in [0, (1<<size)-1]:
            for xor in [0, (1<<size)-1]:
                for p in poly:
                    for reflin in [True,False]:
                        for reflcrc in [True,False]:
                            crc=cls.create(name="CRC",size=size,poly=p,init=init,xor=xor,
                                           reflect_input=reflin, reflect_output=reflcrc)
                            c = crc(msg)
                            if c in targets:
                                print ("Got %%0%ix with %%r" % (size/4))% (c,crc)
                                res.append(crc)
                            smatch = find_substring_from_crc(crc, msg, *targets)
                            if smatch:
                                print "Got substring match with %r: %r" % (crc,smatch)
                                res.append(crc)
        return res
                
    @classmethod
    def autotest(cls):
        failed = 0
        passed = 0
        notdone = 0
        for crc in cls.list:
            if not crc.test_vector:
                print "%15s: no test vector" % crc.name
                notdone += 1
                continue
            tvin,tvout = crc.test_vector
            res = crc(tvin)
            if res == tvout:
                passed += 1
                print "%15s: PASSED: crc(%r)=%#x" % (crc.name,tvin,res)
            else:
                failed += 1
                print "%15s: FAILED: crc(%r)=%#x instead of %#x" % (crc.name,
                                                                    tvin, res,
                                                                    tvout)
        print "PASSED=%i FAILED=%i  Not done=%i" % (passed, failed, notdone)

        return failed == 0

class CRC_16(CRC):
    name = "CRC-16"
    size = 16
    poly = 0x8005
    init = 0
    xor = 0
    reflect_input = True
    reflect_output = True
    test_vector = ("123456789",0xbb3d)

class CRC_32(CRC):
    name = "CRC-32"
    size = 32
    poly = 0x4c11db7
    init = 0xffffffff
    xor = 0xffffffff
    reflect_input = True
    reflect_output = True
    test_vector = ("123456789",0xcbf43926)
 
class A622CRC(CRC):
    name = "CRC A622"
    size = 16
    poly = 0x1021
    init = 0xffff
    xor = 0xffff
    reflect_input = False
    reflect_output = False
    test_vector = ("ADS\x07\x2d",0x9a61)


class CRC_16_CCITT(CRC):
    "aka KERMIT CRC"
    name = "CRC16 CCITT"
    size = 16
    poly = 0x1021
    init = 0
    xor = 0
    reflect_input = True
    reflect_output = True
    test_vector = ("\xcb\x37",0x6b3e)

A618CRC = CRC_16_CCITT

class A620CRC(CRC):
    name = "CRC A620"
    size = 16
    poly = 0x8408
    init = 0xffff
    xor = 0xffff
    reflect_input = True
    reflect_output = False
    header = "\0"
    trailer = "\0"
    test_vector = ("abc",0x6861)




def find_substring_from_crc(CRC, s, *crc):
    l = len(s)
    i = 0
    while i < l:
        j = l
        while j > i:
            sub = s[i:j]
            c = CRC(sub)
#            print "%04x %s" % (c,sub.encode("hex"))
            if c in crc:
                return i,j
            j -= 1
        i += 1



