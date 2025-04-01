---
title: 'WolvCTF 2025 forensic WRITEUP: Passwords'

---

# WolvCTF 2025 forensic WRITEUP: Passwords
![image](https://hackmd.io/_uploads/SkfONylTyx.png)

## Passwords
### Description:
I heard you're a hacker. Can you help me get my passwords back? [Database.kdbx](https://wolvctf.io/files/21058a35157ee169a22fa6526177cc62/Database.kdbx?token=eyJ1c2VyX2lkIjoxMjUzLCJ0ZWFtX2lkIjo2NDksImZpbGVfaWQiOjI5fQ.Z-kgvg.5hqQRKCQxxgVTXZLW_kIdjpBBNw)





### Solution:
> Đầu tiên kiểm tra đây là file gì

```python
┌──(kali㉿kali)-[~/Desktop]
└─$ file Database.kdbx             
Database.kdbx: Keepass password database 2.x KDBX
```
> Keepassdb là file cơ sở dữ liệu được tạo bởi phần mềm KeePass, ta cần phải crack để lấy mã hash
> Sau khi search trên mạng thì mình tìm được tool `keepass2john` thuộc bộ tool `john the ripper` dùng để trích xuất thông tin mã hóa từ file KeePass (.kdbx) và chuyển nó thành định dạng hash phù hợp để sau đó có thể crack bằng `john` hoặc là `hashcat`

![image](https://hackmd.io/_uploads/HJR5WjIa1x.png)

> Sau đó chèn đoãn mã vào file keepass.txt để tiến hành crack bằng `john` và mình lấy `wordlist=rockyou` từ [github](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)

![image](https://hackmd.io/_uploads/BkdnbiUpJx.png)

> Crack thành công, pass là `goblue1`, dùng KeePassXC để mở file `kdbx` với pass vừa crack

![image](https://hackmd.io/_uploads/rJLwQjIa1e.png)

![image](https://hackmd.io/_uploads/B1Udzo8Tkx.png)

![image](https://hackmd.io/_uploads/ByhFfjL6Jg.png)


 flag: `wtcf{1_th0ught_1t_w4s_s3cur3?`
