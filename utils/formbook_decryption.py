# https://github.com/tildedennis/malware/blob/master/formbook/formbook_decryption.py

from Crypto.Cipher import ARC4


class FormBookDecryption:

    def decrypt_func1(self, encbuf, plainbuf_len):
        plainbuf = []

        ebl = [ord(b) for b in encbuf]

        if ebl[0] != 0x55 or ebl[1] != 0x8b:
            print "doesn't start with a function prologue"
            return

        ebl = ebl[3:]
        ei = 0

        while len(plainbuf) < plainbuf_len:
            if ((ebl[ei] - 64) & 0xff) > 31:
                if ((ebl[ei] - 112) & 0xff) > 15:
                    plainbuf, ei = self.decrypt_func1_transform(plainbuf, ebl, ei)
                else:
                    ei += 2
            else:
                plainbuf, ei = self.offset0_byte_1byte(plainbuf, ebl, ei)


        return "".join([chr(b & 0xff) for b in plainbuf])


    def decrypt_func1_transform(self, plainbuf, ebl, ei):
        if ebl[ei] <= 3:
            return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        if ebl[ei] == 4:
            return self.offset1_byte_2bytes(plainbuf, ebl, ei)

        if ebl[ei] == 5:
            return self.offset1_dword_5bytes(plainbuf, ebl, ei)

        if ((ebl[ei] - 8) & 0xff) <= 3:
            return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        if ebl[ei] == 12:
            return self.offset1_byte_2bytes(plainbuf, ebl, ei)

        if ebl[ei] == 13:
            return self.offset1_dword_5bytes(plainbuf, ebl, ei)

        if ebl[ei] == 15:
            ei += 6
            return plainbuf, ei

        if ((ebl[ei] - 16) & 0xff) <= 3:
            return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        if ebl[ei] == 20:
            return self.offset1_byte_2bytes(plainbuf, ebl, ei)

        if ebl[ei] == 21:
            return self.offset1_dword_5bytes(plainbuf, ebl, ei)

        if ((ebl[ei] - 24) & 0xff) <= 3:
            return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        if ebl[ei] == 28:
            return self.offset1_byte_2bytes(plainbuf, ebl, ei)

        if ebl[ei] == 29:
            return self.offset1_dword_5bytes(plainbuf, ebl, ei)

        if ((ebl[ei] - 32) & 0xff) <= 3:
            return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        if ebl[ei] == 36:
            return self.offset1_byte_2bytes(plainbuf, ebl, ei)

        if ebl[ei] == 37:
            return self.offset1_dword_5bytes(plainbuf, ebl, ei)

        if ((ebl[ei] - 40) & 0xff) <= 3:
            return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        if ebl[ei] == 44:
            return self.offset1_byte_2bytes(plainbuf, ebl, ei)

        if ebl[ei] == 45:
            return self.offset1_dword_5bytes(plainbuf, ebl, ei)

        if ((ebl[ei] - 48) & 0xff) <= 3:
            return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        if ebl[ei] == 52:
            return self.offset1_byte_2bytes(plainbuf, ebl, ei)

        if ebl[ei] == 53:
            return self.offset1_dword_5bytes(plainbuf, ebl, ei)

        if ((ebl[ei] - 56) & 0xff) <= 3:
            return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        if ebl[ei] == 60:
            return self.offset1_byte_2bytes(plainbuf, ebl, ei)

        if ebl[ei] == 61:
            return self.offset1_dword_5bytes(plainbuf, ebl, ei)

        if ebl[ei] == 102:
            if ebl[ei+1] == 106:
                plainbuf += ebl[ei+1:ei+1+2]
                ei += 3
            
            if ebl[ei+1] == 104 or ebl[ei+1] == 184:
                plainbuf, ei = self.offset2_short_4bytes(plainbuf, ebl, ei)
            else:
                ei += 1

            return plainbuf, ei

        if ebl[ei] == 104:
            return self.offset1_dword_5bytes(plainbuf, ebl, ei)

        if ebl[ei] == 105:
            plainbuf += ebl[ei+2:ei+2+4]
            plainbuf += ebl[ei+6:ei+6+2]
            ei += 10
            return plainbuf, ei

        if ebl[ei] == 106:
            offset = ebl[ei+1]
            if (offset & 0x80) != 0:
                offset |= 0xffffff00
            plainbuf += ebl[offset:offset+4]
            ei += 2
            return plainbuf, ei

        if ebl[ei] == 107:
            plainbuf += ebl[ei+2:ei+2+4]
            plainbuf += ebl[ei+6:ei+6+2]
            ei += 7
            return plainbuf, ei

        if ebl[ei] == 128:
            if ebl[ei+1] == 5:
                plainbuf += ebl[ei+2:ei+2+4]
                ei += 7
            else:
                plainbuf += ebl[ei+2:ei+2+1]
                ei += 3
            return plainbuf, ei

        if ebl[ei] == 129:
            return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        if ebl[ei] == 131:
            offset = ebl[ei+2]
            if (offset & 0x80) != 0:
                offset |= 0xffffff00
            plainbuf += ebl[offset:offset+4]
            ei += 3

        if ((ebl[ei] + 124) & 0xff) <= 7:
            return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        if ebl[ei] == 141:
            return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        if ebl[ei] == 143:
            return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        if ebl[ei] == 144:
            return self.offset0_byte_1byte(plainbuf, ebl, ei)

        if ((ebl[ei] + 96) & 0xff) <= 3:
            return self.offset1_dword_5bytes(plainbuf, ebl, ei)

        if ((ebl[ei] + 92) & 0xff) <= 3:
            return self.offset0_byte_1byte(plainbuf, ebl, ei)

        if ebl[ei] == 168:
            return self.offset1_byte_2bytes(plainbuf, ebl, ei)

        if ebl[ei] == 169:
            return self.offset1_dword_5bytes(plainbuf, ebl, ei)

        if ((ebl[ei] + 86) & 0xff) <= 5:
            return self.offset0_byte_1byte(plainbuf, ebl, ei)

        if ((ebl[ei] + 80) & 0xff) <= 7:
            return self.offset1_byte_2bytes(plainbuf, ebl, ei)

        if ((ebl[ei] + 72) & 0xff) <= 7:
            return self.offset1_dword_5bytes(plainbuf, ebl, ei)

        if ebl[ei] == 192:
            return self.offset2_dword_7bytes(plainbuf, ebl, ei)

        if ebl[ei] == 193:
            return self.offset2_dword_7bytes(plainbuf, ebl, ei)

        if ebl[ei] == 194:
            return self.offset1_short_3bytes(plainbuf, ebl, ei)

        if ebl[ei] == 195:
            return self.offset0_byte_1byte(plainbuf, ebl, ei)

        if ebl[ei] == 208:
            return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        if ebl[ei] == 209:
            return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        if ebl[ei] == 232 or ebl[ei] == 233:
            ei += 5
            return plainbuf, ei

        if ebl[ei] == 235:
            ei += 2
            return plainbuf, ei

        if ebl[ei] == 242:
            return self.offset0_byte_1byte(plainbuf, ebl, ei)

        if ebl[ei] == 246:
            return self.offset2_byte_3bytes(plainbuf, ebl, ei)

        if ebl[ei] == 247:
            return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        if ebl[ei] == 255:
            if ebl[ei + 1] == 53:
                return self.offset2_dword_6bytes(plainbuf, ebl, ei)

        return plainbuf, ei


    def offset0_byte_1byte(self, plainbuf, ebl, ei):
        plainbuf += [ebl[ei]]
        ei += 1
        return plainbuf, ei


    def offset1_byte_2bytes(self, plainbuf, ebl, ei):
        plainbuf += ebl[ei+1:ei+1+1]
        ei += 2
        return plainbuf, ei


    def offset1_short_3bytes(self, plainbuf, ebl, ei):
        plainbuf += ebl[ei+1:ei+1+2]
        ei += 3 
        return plainbuf, ei


    def offset2_byte_3bytes(self, plainbuf, ebl, ei):
        plainbuf += ebl[ei+2:ei+2+1]
        ei += 3 
        return plainbuf, ei


    def offset2_short_4bytes(self, plainbuf, ebl, ei):
        plainbuf += ebl[ei+2:ei+2+2]
        ei += 4
        return plainbuf, ei


    def offset1_dword_5bytes(self, plainbuf, ebl, ei):
        plainbuf += ebl[ei+1:ei+1+4]
        ei += 5 
        return plainbuf, ei


    def offset2_dword_6bytes(self, plainbuf, ebl, ei):
        plainbuf += ebl[ei+2:ei+2+4]
        ei += 6
        return plainbuf, ei


    def offset2_dword_7bytes(self, plainbuf, ebl, ei):
        plainbuf += ebl[ei+2:ei+2+4]
        ei += 7
        return plainbuf, ei


    def decrypt_func2(self, encbuf, key):
        ebl = [ord(b) for b in encbuf]

        # transform 1
        for i in range(len(encbuf) - 1, 0, -1):
            ebl[i-1] -= ebl[i]

        # transform 2
        for i in range(0, len(encbuf) -1):
            ebl[i] -= ebl[i+1]

        # rc4
        round2 = "".join([chr(b & 0xff) for b in ebl])
        arc4 = ARC4.new(key)
        round3 = arc4.decrypt(round2)

        round3l = [ord(b) for b in round3]

        # transform 3
        for i in range(len(encbuf) - 1, 0, -1):
            round3l[i-1] -= round3l[i]

        # transform 4
        for i in range(0, len(encbuf) -1):
            round3l[i] -= round3l[i+1]

        plainbuf = "".join([chr(b & 0xff) for b in round3l])

        return plainbuf
