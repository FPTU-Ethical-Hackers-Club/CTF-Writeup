---
title: "Write up SVATTTT 2024"
---

# Binary exploitation
---

# Forensics
---
## Easy Forensics

![image](https://github.com/user-attachments/assets/99d4151b-6221-4007-a2a2-f08ee532b427)

Ở bài này, chúng ta sẽ nhận được 2 file như trong hình

![image](https://github.com/user-attachments/assets/f8f127c6-1277-4b87-9629-0d04bae41bdf)

Vậy thì điều đầu tiên mình sẽ head start là dùng Volatility3, một công cụ dùng để thực hiện dynamic memory analysis.

![image](https://github.com/user-attachments/assets/e65f5ac7-9dd6-42ce-bea5-c910a9ff93da)

Ở processlist, mình nhận thấy rằng có FoxitPDFreader và explorer.exe đang chạy và nhận ra rằng lúc mà chúng ta có được file raw này, nó vẫn đang chạy, vì vậy nên theo mình thì lúc đó, user đang làm gì với 2 process này. Nhưng mà sau khi để ý kĩ thì mình thấy rằng PDFreader đã dừng còn explorer vẫn tiếp tục chạy.

Tiếp theo, mình dùng envars để check username của máy này.

![image](https://github.com/user-attachments/assets/2848909a-57c4-45f2-9fb9-0b490afc8c80)

Giờ thì mình có được username của process explorer.exe là vboxuser, tiếp theo mình dùng plugin filescan và lúc này mình thấy 1 file tên là 5.exe

![image](https://github.com/user-attachments/assets/0ccc0684-1c4c-402d-b117-b4cba0b0a691)

Mình sẽ tiếp tục dump nó về để kiểm tra bằng plugin filedump. Sau khi filedump thì mình có file 5.exe để phân tích. 

file 5.exe thứ nhất:

![image](https://github.com/user-attachments/assets/229ea318-5e06-4218-9e0b-08b09ef0e0b2)

file 5.exe thứ hai:

![image](https://github.com/user-attachments/assets/914fb991-6df0-4309-9c24-9a98bc148809)

Mình để ý rằng có 1 dòng base64 ở đây, mình sẽ thử decode nó

![image](https://github.com/user-attachments/assets/0ee48d82-cc43-42be-8c09-aa6097daf052)

Nó cho mình 1 cái password gì đó ? Lúc này mình nhớ về file gift.rar

![image](https://github.com/user-attachments/assets/8ad4aad0-b09a-42de-8d63-cbafd5d599a9)

Nó cần mật khẩu, vậy thì mình đoán nó sẽ là cái pass decode kia

![image](https://github.com/user-attachments/assets/d1d12999-f9ed-4db3-a5fd-60ae292ca4b7)

Ye và nó đúng

![image](https://github.com/user-attachments/assets/274e6858-e7a7-4323-a8b4-525d10066e22)

FLAG: ASCIS{Gh4st1n_Th3_R2M}

