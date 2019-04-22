# this is a standalone single-file merge of aplib compression and decompression
# taken from my own library Kabopan http://code.google.com/p/kabopan/
# (no other clean-up or improvement)

# Ange Albertini, BSD Licence, 2007-2011

# from kbp\comp\_lz77.py  ##################################################
def find_longest_match(s, sub):
    """returns the number of byte to look backward and the length of byte to copy)"""
    if sub == "":
        return 0, 0
    limit = len(s)
    dic = s[:]
    l = 0
    offset = 0
    length = 0
    first = 0
    word = ""

    word += sub[l]
    pos = dic.rfind(word, 0, limit + 1)
    if pos == -1:
        return offset, length

    offset = limit - pos
    length = len(word)
    dic += sub[l]

    while l < len(sub) - 1:
        l += 1
        word += sub[l]

        pos = dic.rfind(word, 0, limit + 1)
        if pos == -1:
            return offset, length
        offset = limit - pos
        length = len(word)
        dic += sub[l]
    return offset, length

# from _misc.py ###############################

def int2lebin(value, size):
    """ouputs value in binary, as little-endian"""
    result = ""
    for i in xrange(size):
        result = result + chr((value >> (8 * i)) & 0xFF )
    return result

def modifystring(s, sub, offset):
    """overwrites 'sub' at 'offset' of 's'"""
    return s[:offset] + sub + s[offset + len(sub):]

def getbinlen(value):
    """return the bit length of an integer"""
    result = 0
    if value == 0:
        return 1
    while value != 0:
        value >>= 1
        result += 1
    return result

# from kbp\_bits.py  #################################
class _bits_compress():
    """bit machine for variable-sized auto-reloading tag compression"""
    def __init__(self, tagsize):
        """tagsize is the number of bytes that takes the tag"""
        self.out = ""

        self.__tagsize = tagsize
        self.__tag = 0
        self.__tagoffset = -1
        self.__maxbit = (self.__tagsize * 8) - 1
        self.__curbit = 0
        self.__isfirsttag = True


    def getdata(self):
        """builds an output string of what's currently compressed:
        currently output bit + current tag content"""
        tagstr = int2lebin(self.__tag, self.__tagsize)
        return modifystring(self.out, tagstr, self.__tagoffset)

    def write_bit(self, value):
        """writes a bit, make space for the tag if necessary"""
        if self.__curbit != 0:
            self.__curbit -= 1
        else:
            if self.__isfirsttag:
                self.__isfirsttag = False
            else:
                self.out = self.getdata()
            self.__tagoffset = len(self.out)
            self.out += "".join(["\x00"] * self.__tagsize)
            self.__curbit = self.__maxbit
            self.__tag = 0

        if value:
            self.__tag |= (1 << self.__curbit)
        return

    def write_bitstring(self, s):
        """write a string of bits"""
        for c in s:
            self.write_bit(0 if c == "0" else 1)
        return

    def write_byte(self, b):
        """writes a char or a number"""
        assert len(b) == 1 if isinstance(b, str) else 0 <= b <= 255
        self.out += b[0:1] if isinstance(b, str) else chr(b)
        return

    def write_fixednumber(self, value, nbbit):
        """write a value on a fixed range of bits"""
        for i in xrange(nbbit - 1, -1, -1):
            self.write_bit( (value >> i) & 1)
        return

    def write_variablenumber(self, value):
        assert value >= 2

        length = getbinlen(value) - 2 # the highest bit is 1
        self.write_bit(value & (1 << length))
        for i in xrange(length - 1, -1, -1):
            self.write_bit(1)
            self.write_bit(value & (1 << i))
        self.write_bit(0)
        return

class _bits_decompress():
    """bit machine for variable-sized auto-reloading tag decompression"""
    def __init__(self, data, tagsize):
        self.__curbit = 0
        self.__offset = 0
        self.__tag = None
        self.__tagsize = tagsize
        self.__in = data
        self.out = ""

    def getoffset(self):
        """return the current byte offset"""
        return self.__offset

#    def getdata(self):
#        return self.__lzdata

    def read_bit(self):
        """read next bit from the stream, reloads the tag if necessary"""
        if self.__curbit != 0:
            self.__curbit -= 1
        else:
            self.__curbit = (self.__tagsize * 8) - 1
            self.__tag = ord(self.read_byte())
            for i in xrange(self.__tagsize - 1):
                self.__tag += ord(self.read_byte()) << (8 * (i + 1))

        bit = (self.__tag  >> ((self.__tagsize * 8) - 1)) & 0x01
        self.__tag <<= 1
        return bit

    def is_end(self):
        return self.__offset == len(self.__in) and self.__curbit == 1

    def read_byte(self):
        """read next byte from the stream"""
        if type(self.__in) == str:
            result = self.__in[self.__offset]
        elif type(self.__in) == file:
            result = self.__in.read(1)
        self.__offset += 1
        return result

    def read_fixednumber(self, nbbit, init=0):
        """reads a fixed bit-length number"""
        result = init
        for i in xrange(nbbit):
            result = (result << 1)  + self.read_bit()
        return result

    def read_variablenumber(self):
        """return a variable bit-length number x, x >= 2

        reads a bit until the next bit in the pair is not set"""
        result = 1
        result = (result << 1) + self.read_bit()
        while self.read_bit():
            result = (result << 1) + self.read_bit()
        return result

    def read_setbits(self, max_, set_=1):
        """read bits as long as their set or a maximum is reached"""
        result = 0
        while result < max_ and self.read_bit() == set_:
            result += 1
        return result

    def back_copy(self, offset, length=1):
        for i in xrange(length):
            self.out += self.out[-offset]
        return

    def read_literal(self, value=None):
        if value is None:
            self.out += self.read_byte()
        else:
            self.out += value
        return False

# from kbp\comp\aplib.py ###################################################
"""
aPLib, LZSS based lossless compression algorithm

Jorgen Ibsen U{http://www.ibsensoftware.com}
"""

def lengthdelta(offset):
    if offset < 0x80 or 0x7D00 <= offset:
        return 2
    elif 0x500 <= offset:
        return 1
    return 0

class compress(_bits_compress):
    """
    aplib compression is based on lz77
    """
    def __init__(self, data, length=None):
        _bits_compress.__init__(self, 1)
        self.__in = data
        self.__length = length if length is not None else len(data)
        self.__offset = 0
        self.__lastoffset = 0
        self.__pair = True
        return

    def __literal(self, marker=True):
        if marker:
            self.write_bit(0)
        self.write_byte(self.__in[self.__offset])
        self.__offset += 1
        self.__pair = True
        return

    def __block(self, offset, length):
        assert offset >= 2
        self.write_bitstring("10")

        # if the last operations were literal or single byte
        # and the offset is unchanged since the last block copy
        # we can just store a 'null' offset and the length
        if self.__pair and self.__lastoffset == offset:
            self.write_variablenumber(2)    # 2-
            self.write_variablenumber(length)
        else:
            high = (offset >> 8) + 2
            if self.__pair:
                high += 1
            self.write_variablenumber(high)
            low = offset & 0xFF
            self.write_byte(low)
            self.write_variablenumber(length - lengthdelta(offset))
        self.__offset += length
        self.__lastoffset = offset
        self.__pair = False
        return

    def __shortblock(self, offset, length):
        assert 2 <= length <= 3
        assert 0 < offset <= 127
        self.write_bitstring("110")
        b = (offset << 1 ) + (length - 2)
        self.write_byte(b)
        self.__offset += length
        self.__lastoffset = offset
        self.__pair = False
        return

    def __singlebyte(self, offset):
        assert 0 <= offset < 16
        self.write_bitstring("111")
        self.write_fixednumber(offset, 4)
        self.__offset += 1
        self.__pair = True
        return

    def __end(self):
        self.write_bitstring("110")
        self.write_byte(chr(0))
        return

    def do(self):
        self.__literal(False)
        while self.__offset < self.__length:
            offset, length = find_longest_match(self.__in[:self.__offset],
                self.__in[self.__offset:])
            if length == 0:
                c = self.__in[self.__offset]
                if c == "\x00":
                    self.__singlebyte(0)
                else:
                    self.__literal()
            elif length == 1 and 0 <= offset < 16:
                self.__singlebyte(offset)
            elif 2 <= length <= 3 and 0 < offset <= 127:
                self.__shortblock(offset, length)
            elif 3 <= length and 2 <= offset:
                self.__block(offset, length)
            else:
                self.__literal()
                #raise ValueError("no parsing found", offset, length)
        self.__end()
        return self.getdata()


class decompress(_bits_decompress):
    def __init__(self, data):
        _bits_decompress.__init__(self, data, tagsize=1)
        self.__pair = True    # paired sequence
        self.__lastoffset = 0
        self.__functions = [
            self.__literal,
            self.__block,
            self.__shortblock,
            self.__singlebyte]
        return

    def __literal(self):
        self.read_literal()
        self.__pair = True
        return False

    def __block(self):
        b = self.read_variablenumber()    # 2-
        if b == 2 and self.__pair :    # reuse the same offset
            offset = self.__lastoffset
            length = self.read_variablenumber()    # 2-
        else:
            high = b - 2    # 0-
            if self.__pair:
                high -= 1
            offset = (high << 8) + ord(self.read_byte())
            length = self.read_variablenumber()    # 2-
            length += lengthdelta(offset)
        self.__lastoffset = offset
        self.back_copy(offset, length)
        self.__pair = False
        return False

    def __shortblock(self):
        b = ord(self.read_byte())
        if b <= 1:    # likely 0
            return True
        length = 2 + (b & 0x01)    # 2-3
        offset = b >> 1    # 1-127
        self.back_copy(offset, length)
        self.__lastoffset = offset
        self.__pair = False
        return False

    def __singlebyte(self):
        offset = self.read_fixednumber(4) # 0-15
        if offset:
            self.back_copy(offset)
        else:
            self.read_literal('\x00')
        self.__pair = True
        return False

    def do(self):
        """returns decompressed buffer and consumed bytes counter"""
        self.read_literal()
        while True:
            if self.__functions[self.read_setbits(3)]():
                break
        return self.out, self.getoffset()

if __name__ == "__main__":
# from kbp\test\aplib_test.py ######################################################################
    assert decompress(compress("a").do()).do() == ("a", 3)
    assert decompress(compress("ababababababab").do()).do() == ('ababababababab', 9)
    assert decompress(compress("aaaaaaaaaaaaaacaaaaaa").do()).do() == ('aaaaaaaaaaaaaacaaaaaa', 11)

