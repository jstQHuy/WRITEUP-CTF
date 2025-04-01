---
title: SwampCTF 2025 forensic WRITEUP

---

# SwampCTF 2025 forensic WRITEUP
![image](https://hackmd.io/_uploads/HyYfJj8pyg.png)


## List
- [Homework Help (50pts)](##1.-Homework-Help)
- [Preferential Treatment (150pts)](##2.-Preferential-Treatment)
- [Planetary Storage (200pts)](##3.-Planetary-Storage)
- [MuddyWater (200pts)](##4.-MuddyWater)
- [Proto Proto (214pts)](##5.-Proto-Proto)

## 1. Homework Help
### Description:
I accidently lost some of my class notes! Can you help me recover it? (Note: Unzipped size is 4GB)
[SWAMP_d_image.zip](https://ctf.swampctf.com/files/e399e62814591af3a8c33cce90c861f8/SWAMP_D_image.zip?token=eyJ1c2VyX2lkIjoxNTE2LCJ0ZWFtX2lkIjo3NDMsImZpbGVfaWQiOjI5fQ.Z-koJg.Zf56u6naCUWy2qTReMzebRJlHWI)

>unzip và thấy đây là file `.VHD`, up file lên autopsy và mò ra flag


![image](https://hackmd.io/_uploads/H1PcyVYakx.png)

Flag: `swampCTF{n0thing_i5_3v3r_d3l3t3d}`





## 2. Preferential Treatment
### Description:
We have an old Windows Server 2008 instance that we lost the password for. Can you see if you can find one in this packet capture?
[gpnightmare.pcap](https://ctf.swampctf.com/files/2211e0ac61f19713bb139806967bd267/gpnightmare.pcap?token=eyJ1c2VyX2lkIjoxNTE2LCJ0ZWFtX2lkIjo3NDMsImZpbGVfaWQiOjE0fQ.Z-kpmw.vpHu9ejwpZlgneYqd_jVIc6VM44)

>Bài này khá đơn giản, ta chỉ cần `Follow TCP Stream`, chỉ có 1 stream, và decrypt bằng `gcc-decrypt` là ra flag


![image](https://hackmd.io/_uploads/Hysd2Q_pJg.png)

```python
┌──(kali㉿kali)-[~/Desktop]
└─$ gpp-decrypt dAw7VQvfj9rs53A8t4PudTVf85Ca5cmC1Xjx6TpI/cS8WD4D8DXbKiWIZslihdJw3Rf+ijboX7FgLW7pF0K6x7dfhQ8gxLq34ENGjN8eTOI=
swampCTF{4v3r463_w1nd0w5_53cur17y}
```
Flag: `swampCTF{4v3r463_w1nd0w5_53cur17y}`


## 3. Planetary Storage
### Description:
My friend found this strange file while perusing his computer, but we can't read it. Can you figure out what it is and get the information from it?

Difficulty: Easy/Medium

The flag is in the standard format.
[PlanetaryStorage.zip](https://ctf.swampctf.com/files/e763c3f65b8404b65b880f6c9d35f0f0/PlanetaryStorage.zip?token=eyJ1c2VyX2lkIjoxNTE2LCJ0ZWFtX2lkIjo3NDMsImZpbGVfaWQiOjExfQ.Z-kp8A.BqP8I6ULfAsfWAHoFsQSQe2s2CM)
>unzip thì ra được một đống file

![image](https://hackmd.io/_uploads/By0QfEK61e.png)
>strings từng file ldb thì có file 000010.ldb, mình `base64 -d` 2 lần thì ra flag

![image](https://hackmd.io/_uploads/H1sGf4FTJe.png)
Flag: `swampCTF{1pf5-b453d-d474b453}`


## 4. MuddyWater
### Description:
We caught a threat actor, called MuddyWater, bruteforcing a login for our Domain Controller. We have a packet capture of the intrustion. Can you figure out which account they logged in to and what the password is?

Flag format is `swampCTF{<username>:<password>}`
[muddywater.pcap](https://ctf.swampctf.com/files/c0644099bc8e896f924e72858f29c64f/muddywater.pcap?token=eyJ1c2VyX2lkIjoxNTE2LCJ0ZWFtX2lkIjo3NDMsImZpbGVfaWQiOjMyfQ.Z-kqLw.gm4uzI_UIMQbYi79UPVpkr-iCg0)

> Down file pcap và xem có gì hot

![image](https://hackmd.io/_uploads/HkKxJVOp1l.png)

> Theo như trong ảnh và description mà bài đã nói thì khả năng bài này là đi phân tích các gói tin SMB(Session Setup) vì attacker đã bruteforce thông qua giao thức SMB

> Có thể thấy rất nhiều gói tin Session Setup Request từ cùng 1 IP (client) → server.
Server trả về:
NT_STATUS = 0xc000006d → Sai mật khẩu (thất bại)
NT_STATUS = 0x00000000 → Đúng mật khẩu (thành công)
tham khảo thêm về [NTSTATUS Values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)

>sol: ta phải tìm những gói tin thành công bằng filter `smb2.status=0x00000000`


![image](https://hackmd.io/_uploads/B1RLnXOaJl.png)

>Xuất hiện nhiều gói `Negotiate`, sure vì gói Negotiate này luôn có NT_STATUS = 0x00000000 (thành công) vì nó chỉ là thương lượng giao thức, sau khi đợi server chọn phiên bản smb thì client mới gửi lên gói `Session Setup` chứa username/pass


![image](https://hackmd.io/_uploads/HJ24HVupJe.png)

![image](https://hackmd.io/_uploads/rk67mXFa1l.png)

>Đây là packet thành công mà server đã trả cho client với
>`Account: hackbackzip`
`Domain: DESKTOP-0TNOE4V` 
và đây là gói tin trả lời request cho gói tin 72069, kiểm tra gói tin này và kiểm tra NTLM_challenge bằng `tcp.stream==6670`

![image](https://hackmd.io/_uploads/BkeC77takg.png)

![image](https://hackmd.io/_uploads/SkovE7F6ke.png)


> Cấu trúc chuẩn của NTLMv2 Hash `User::Domain:ServerChallenge:NTProofStr:NTLMv2Response`, lấy các thông tin mà mình đã khoanh đỏ trong hình và sau đó crack bằng `john` và `wordlist=rockyou`

> đầu tiên thì  lưu hash vào `muddy.txt`

```python
┌──(kali㉿kali)-[~/Desktop]
└─$ cat muddy.txt
hackbackzip::DESKTOP-0TNOE4V:d102444d56e078f4:eb1b0afc1eef819c1dccd514c9623201:001010000000000006f233d3d9f9edb01755959535466696d0000000002001e004400450053004b0054004f0050002d00300054004e004f0045003400560001001e004400450053004b0054004f0050002d00300054004e004f0045003400560004001e004400450053004b0054004f0050002d00300054004e004f0045003400560003001e004400450053004b0054004f0050002d00300054004e004f00450034005600070008006f233d3d9f9edb010900280063006900660073002f004400450053004b0054004f0050002d00300054004e004f004500340056000000000000000000
```
>Crack

![image](https://hackmd.io/_uploads/Sk9QC4OaJg.png)

Flag: `swampCTF{hackbackzip:pikeplace}`

## 5. Proto Proto
### Description:
Moto Moto likes you. But not enough to explain how his server works. We got a pcap of the client and server communicating. Can you figure out how the server works and retrieve the flag?
`chals.swampctf.com:44254`
[proto_proto.pcap](https://ctf.swampctf.com/files/c0cd709d29c1c287368e71dd1b779814/proto_proto.pcap?token=eyJ1c2VyX2lkIjoxNTE2LCJ0ZWFtX2lkIjo3NDMsImZpbGVfaWQiOjE1fQ.Z-kqbw.WaRPfWkQ9dXoUQS1dksItk45NIo)

![image](https://hackmd.io/_uploads/Bkg59mtaJx.png)
>Đầu tiên khi mở file, mình tưởng đây là bài decrypt TLS nhưng mà bài không cung cấp key, làm đi tìm cert mà không có=)))))))))))

>Sau đó thì có `Follow TCP Stream` và `Follow UDP Stream` 

![image](https://hackmd.io/_uploads/SJTa5QtTJx.png)

>Từ network stream, có thể thấy client gửi flag.txt và được server phản hồi thông qua UDP

![image](https://hackmd.io/_uploads/ryN1C7t6yl.png)

> Tương tự, ta cũng sẽ gửi "flag.txt" lên server thông qua UDP, nhưng mà sẽ gửi values của "flag.txt" dưới dạng bytes qua nc với payload `\x02\x08\x66\x6c\x61\x67\x2e\x74\x78\x74`

```python
┌──(kali㉿kali)-[~/Desktop]
└─$ echo -ne '\x02\x08\x66\x6c\x61\x67\x2e\x74\x78\x74'|nc -u chals.swampctf.com 44254
swampCTF{r3v3r53_my_pr070_l1k3_m070_m070}
```
- `-ne` không xuống dòng và bật chế độ interpret backslash escapes - ví dụ hiểu được `\x02`
- `-u` netcat gửi qua phương thức udp

Flag: `swampCTF{r3v3r53_my_pr070_l1k3_m070_m070}`




