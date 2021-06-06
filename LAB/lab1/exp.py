import r2pipe, json, pwn

r = r2pipe.open('sysmagic')

key = ''.join([ 
    pwn.re.findall("'(.*)'", r.cmd(f'pd 1 @0x080485af+{7 * i}')).pop() 
    for i in range(((0x08048603 - 0x080485af) // 7) + 1) ## dword
])

enc = [
    int(json.loads(r.cmd(f'pdj 1 @0x08048609+{4 * i}')).pop()['disasm'].split(', ').pop(), 16)
    for i in range(((0x080486c9 - 0x08048609) // 4) + 1) ## byte
]

pwn.info(pwn.xor(enc, key))