# MIT License
#
# Copyright (c) 2023 Andrey Zhdanov (rivitna)
# https://github.com/rivitna
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import sys
import io
import struct


ENTRY_SIGN = b'\xD3\x45'
ENTRY_SIGN2 = b'\xDB\xE8\xC5\x01'

RESDATA_SIGN = b'\x0B\xAD'

ENTRY_HDR_SIZE = 0x3C

KEY = \
b'\x1E\x87\x78\x1B\x8D\xBA\xA8\x44\xCE\x69\x70\x2C\x0C\x78\xB7\x86' \
b'\xA3\xF6\x23\xB7\x38\xF5\xED\xF9\xAF\x83\x53\x0F\xB3\xFC\x54\xFA' \
b'\xA2\x1E\xB9\xCF\x13\x31\xFD\x0F\x0D\xA9\x54\xF6\x87\xCB\x9E\x18' \
b'\x27\x96\x97\x90\x0E\x53\xFB\x31\x7C\x9C\xBC\xE4\x8E\x23\xD0\x53' \
b'\x71\xEC\xC1\x59\x51\xB8\xF3\x64\x9D\x7C\xA3\x3E\xD6\x8D\xC9\x04' \
b'\x7E\x82\xC9\xBA\xAD\x97\x99\xD0\xD4\x58\xCB\x84\x7C\xA9\xFF\xBE' \
b'\x3C\x8A\x77\x52\x33\x55\x7D\xDE\x13\xA8\xB1\x40\x87\xCC\x1B\xC8' \
b'\xF1\x0F\x6E\xCD\xD0\x83\xA9\x59\xCF\xF8\x4A\x9D\x1D\x50\x75\x5E' \
b'\x3E\x19\x18\x18\xAF\x23\xE2\x29\x35\x58\x76\x6D\x2C\x07\xE2\x57' \
b'\x12\xB2\xCA\x0B\x53\x5E\xD8\xF6\xC5\x6C\xE7\x3D\x24\xBD\xD0\x29' \
b'\x17\x71\x86\x1A\x54\xB4\xC2\x85\xA9\xA3\xDB\x7A\xCA\x6D\x22\x4A' \
b'\xEA\xCD\x62\x1D\xB9\xF2\xA2\x2E\xD1\xE9\xE1\x1D\x75\xBE\xD7\xDC' \
b'\x0E\xCB\x0A\x8E\x68\xA2\xFF\x12\x63\x40\x8D\xC8\x08\xDF\xFD\x16' \
b'\x4B\x11\x67\x74\xCD\x0B\x9B\x8D\x05\x41\x1E\xD6\x26\x2E\x42\x9B' \
b'\xA4\x95\x67\x6B\x83\x98\xDB\x2F\x35\xD3\xC1\xB9\xCE\xD5\x26\x36' \
b'\xF2\x76\x5E\x1A\x95\xCB\x7C\xA4\xC3\xDD\xAB\xDD\xBF\xF3\x82\x53'


def rc4_ksa(key):
    """RC4 KSA"""

    key_len = len(key)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % key_len]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s


def rc4_prga(s):
    """RC4 PRGA"""

    i = 0
    j = 0
    while True:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[j], s[i] = s[i], s[j]
        yield s[(s[i] + s[j]) & 0xFF]


def rc4_encrypt(data, key):
    """Encrypt/decrypt data"""

    s = rc4_ksa(key)
    keystream = rc4_prga(s)

    res_data = bytearray(data)

    for i in range(len(res_data)):
        res_data[i] ^= next(keystream)

    return bytes(res_data)


def decrypt_resdata(enc_data):
    """Decrypt Defender ResourceData"""

    if enc_data[:len(RESDATA_SIGN)] != RESDATA_SIGN:
        return None

    return rc4_encrypt(enc_data, KEY)


def decrypt_entry(enc_data):
    """Decrypt Defender Entry"""

    if ((len(enc_data) < ENTRY_HDR_SIZE) or
        (enc_data[:len(ENTRY_SIGN)] != ENTRY_SIGN)):
        return None

    # Decrypt header
    hdr_data = rc4_encrypt(enc_data[:ENTRY_HDR_SIZE], KEY)

    if hdr_data[:len(ENTRY_SIGN2)] != ENTRY_SIGN2:
        return None

    enc_data = enc_data[ENTRY_HDR_SIZE:]

    # Extract and decrypt metadata
    metadata1_len, metadata2_len = struct.unpack_from('<LL', hdr_data, 0x28)
    print('Metadata #1: %d bytes' % metadata1_len)
    print('Metadata #2: %d bytes' % metadata2_len)

    enc_metadata1 = enc_data[:metadata1_len]
    metadata1 = rc4_encrypt(enc_metadata1, KEY)

    enc_metadata2 = enc_data[metadata1_len : metadata1_len + metadata2_len]
    metadata2 = rc4_encrypt(enc_metadata2, KEY)

    return metadata1, metadata2


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', sys.argv[0], 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open(filename, 'rb') as f:
    enc_data = f.read()

if enc_data[:len(RESDATA_SIGN)] == RESDATA_SIGN:
    # Decrypt Defender ResourceData
    print('Defender ResourceData file')
    data = decrypt_resdata(enc_data)
    with io.open(filename + '.dec', 'wb') as f:
        f.write(data)

elif enc_data[:len(ENTRY_SIGN)] == ENTRY_SIGN:
    # Decrypt Defender Entry
    print('Defender Entry file')
    metadata1, metadata2 = decrypt_entry(enc_data)
    with io.open(filename + '.met1', 'wb') as f:
        f.write(metadata1)
    with io.open(filename + '.met2', 'wb') as f:
        f.write(metadata2)

else:
    print('Error: Invalid Defender Quarantine file')
    sys.exit(1)

print('Done!')
