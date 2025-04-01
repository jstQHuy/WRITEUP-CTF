---
title: PicoCTF 2025 forensic WRITEUP

---

```

```
# PicoCTF 2025 forensic WRITEUP
       
![image](https://hackmd.io/_uploads/S1ckwyea1x.png)

## List
- [RED](##1.-RED)
- [Ph4nt0m 1ntrud3r](#2.-Ph4nt0m-1ntrud3r)
- [Bitlocker-1](#3.-Bitlocker-1)
- [flags are stepic](#4.-flags-are-stepic)
- [~~Event-Viewing~~](#5.-Event-Viewing)
- [Bitlocker-2](#6.-Bitlocker-2)

## 1. RED
### Description: RED, RED, RED
Download the image: [red.png](https://challenge-files.picoctf.net/c_verbal_sleep/831307718b34193b288dde31e557484876fb84978b5818e2627e453a54aa9ba6/red.png) 
 >Sau khi download, dùng exiftool và zsteg để kiểm tra file png
 
```python
└─$ exiftool red.png
```
 ![image](https://hackmd.io/_uploads/SJx1Udn3kl.png)
 >Dùng exiftool không có gì đặc biệt, chỉ toàn là metadata của ảnh, sử dụng zsteg để xem có dữ liệu giấu bên trong file không

```python
└─$ zsteg red.png
```
![image](https://hackmd.io/_uploads/rkYPLOnhJx.png)
>Phát hiện đoạn mã có định dạng base64, cop và đưa lên [cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false))

![image](https://hackmd.io/_uploads/r1HsL_nhye.png)

flag :    `picoCTF{r3d_1s_th3_ult1m4t3_cur3_f0r_54dn355_}`
      
     
## 2. Ph4nt0m 1ntrud3r
### Description:
A digital ghost has breached my defenses, and my sensitive data has been stolen! 😱💻 Your mission is to uncover how this phantom intruder infiltrated my system and retrieve the hidden flag. To solve this challenge, you'll need to analyze the provided PCAP file and track down the attack method. The attacker has cleverly concealed his moves in well timely manner. Dive into the network traffic, apply the right filters and show off your forensic prowess and unmask the digital intruder! Find the PCAP file here [Network Traffic PCAP file](https://challenge-files.picoctf.net/c_verbal_sleep/45a9df82c8f05fd74b8547d157ae6b1be6ba783a2bad55c6f8c664e4609d88ac/myNetworkTraffic.pcap) and try to get the flag.

 - Mở file PCAP bằng Wireshark, chủ yếu là các packet được gửi qua phương thức TCP
 
![image](https://hackmd.io/_uploads/HyENYd23Jx.png)
 - Follow TCP stream

![image](https://hackmd.io/_uploads/Hkk8q_h2Jl.png)

 - Mỗi packet đều có một tcp data encoding dùng base64
 
 ![image](https://hackmd.io/_uploads/Hk4Ncuh2yg.png)
 ![image](https://hackmd.io/_uploads/SkoU9dnh1e.png)
 ![image](https://hackmd.io/_uploads/BJALcO3hJl.png)
>Vân vân, và để ý rằng khi bắt, những packets này không được sắp xếp theo thứ tự thời gian, ta sẽ ghép các fragmentation này lại từ những đoạn mã base64 và ghép lại thì sẽ ra flag

 - Dùng tshark để lấy tcp data từng packet
 
```python
└─$ tshark -r myNetworkTraffic.pcap -Y "tcp" -T fields -e tcp.segment_data | xxd -p -r| base64 -d
```
>Sử dụng lệnh này để trích xuất tcp data từ dạng hex về binary gốc ( vì khi trích xuất dữ liệu từ PCAP, có thể nhận được dữ liệu ở dạng hex), kết hợp với lệnh base64 -d để decode vì có để ý đoạn này có định dạng base64
- `-r` để đọc file pcap
- `-Y` để dùng bộ lọc và lọc các packet sử dụng phương thức tcp
- `-T fields -e tcp.segment_data` để lấy data của các gói tcp, -T fields luôn đi với -e

![image](https://hackmd.io/_uploads/rJDja_32yl.png)
>Nhưng mình không lấy đúng định dạng của flag, như đã nói thì dùng thêm prefix      `e.frametime` để lấy data theo thời gian được sort lại
 
 ```python
└─$ tshark -r myNetworkTraffic.pcap -Y “tcp.len==4 || tcp.len==8|| tcp.len==12” -T fields -e tcp.segment_data -e frame.time 
```
   ![image](https://hackmd.io/_uploads/SJOkGth3kl.png)
>[!Tip] Sau đó ta sẽ sử dụng sort cho cột frame.time và in ra cột segment_data 

```python
└─$ tshark -r myNetworkTraffic.pcap -Y "tcp.len==4||tcp.len==8||tcp.len==12" -T fields -e tcp.segment_data -e frame.time |sort -k2| awk '{print $1}'| xxd -p -r|base64 -d  
```
 -   `sort -k2` để sắp xếp dữ liệu theo cột `frame.time`
 -   `awk '{print $1}'` để print ra dữ liệu cột `segment_data`
 
   ![image](https://hackmd.io/_uploads/Sk5tMY3nkx.png)
flag :       `picoCTF{r3d_1s_th3_ult1m4t3_cur3_f0r_54dn355_}`

## 3. Bitlocker-1

### Description: 
Jacky is not very knowledgable about the best security passwords and used a simple password to encrypt their BitLocker drive. See if you can break through the encryption!
Download the disk image [here](https://challenge-files.picoctf.net/c_verbal_sleep/9e934e4d78276b12e27224dac16e50e6bbeae810367732eee4d5e38e6b2bb868/bitlocker-1.dd)

> Sau khi tìm hiểu thì thấy image file của ổ đĩa mã hóa bằng BitLocker. BitLocker là một công nghệ mã hóa toàn bộ ổ đĩa của Microsoft, và do đó, hệ thống yêu cầu ta cung cấp mật khẩu hoặc khóa giải mã để có thể truy cập được dữ liệu.

> Đầu tiên ta phải lấy mã hash cho password sau đó crack hash này để lấy pass

```python
└─$ bitlocker2john -i bitlocker-1.dd
```

```python=
User Password hash: 
$bitlocker$0$16$cb4809fe9628471a411f8380e0f668db$1048576$12$d04d9c58eed6da010a000000$60$68156e51e53f0a01c076a32ba2b2999afffce8530fbe5d84b4c19ac71f6c79375b87d40c2d871ed2b7b5559d71ba31b6779c6f41412fd6869442d66d
```
> Lưu đoạn mã hash này vào 1 file `john.txt`, sau đó mình dùng john để crack bằng cách bruteforce mk bằng `wordlist rockyou.txt` clone từ [github](https://github.com/openethereum/wordlist/blob/master/res/wordlist.txt) bằng lệnh 

```python
└─$ john --wordlist=./rockyou.txt -- format=bitlocker john.txt
``` 
 ![image](https://hackmd.io/_uploads/H14g7tpnJe.png)
>[!Tip] Pass là jacqueline, sau đó dùng dislocker(tool dùng để mở và đọc ổ đĩa được mã hóa bằng BitLocker) với mật khẩu vừa tìm được với câu lệnh

```python
sudo mkdir /mnt/bitlocker
```
```python
sudo mkdir /mnt/flag-file
```
```python
sudo dislocker -r -V bitlocker-1.dd -ujacqueline --/mnt/bitlocker
```
-    `-r` read only
-    `-V` Verbose - chỉ định file disk img
-    `-ujacqueline` pass


![image](https://hackmd.io/_uploads/BJSRTD02yx.png)
![image](https://hackmd.io/_uploads/H17l0DAhJe.png)
Sau đó mình mount file này bằng lệnh
```python
mount -o loop /mnt/bitlocker/dislocker-file /mnt/flag-file   
```
>Khi ta sử dụng dislocker, nó sẽ tạo ra một file dislocker-file, chứa dữ liệu đã được giải mã từ ổ đĩa BitLocker. Ta không thể mount file này trực tiếp như một ổ đĩa vật lý, vì vậy `-o loop` cho phép chuyển file này thành một thiết bị ổ đĩa ảo để có thể truy cập vào dữ liệu bên trong.
>
![image](https://hackmd.io/_uploads/By5jbO0hyg.png)
flag: `picoCTF{us3_b3tt3r_p4ssw0rd5_pl5!_3242adb1}`

## 4. flags are stepic
### Description:
A group of underground hackers might be using this legit site to communicate. Use your forensic techniques to uncover their message
Try it [here!](http://standard-pizzas.picoctf.net:55838/)
>Hints: In the country that doesn't exist, the flag persists

> Dựa vào hint mà bài cho, nhờ cả gpt4 mà mình tìm được cờ Upanzi không được tính là quốc gia

> Nhưng mà down về, thử binwalk, zsteg, steghide, exif.... thậm chí là cả [aperisolve](https://www.aperisolve.com/) cũng không có kết quả gì 

>Lần mò trên mạng thì tìm được tool stepic=)))) gợi ý từ tên đề bài
![image](https://hackmd.io/_uploads/ByozhnAhkx.png)


```python=1
┌──(kali㉿kali)-[~/Desktop]
└─$ stepic -d -i upz.png -o flag.txt
/usr/lib/python3/dist-packages/PIL/Image.py:3402: DecompressionBombWarning: Image size (150658990 pixels) exceeds limit of 89478485 pixels, could be decompression bomb DOS attack.
  warnings.warn(
                 
┌──(kali㉿kali)-[~/Desktop]
└─$ cat flag.txt 
picoCTF{fl4g_h45_fl4g57f48d94} 
```
flag: `picoCTF{fl4g_h45_fl4g57f48d94}`
## 5. ~~Event-Viewing~~
### Description:
One of the employees at your company has their computer infected by malware! Turns out every time they try to switch on the computer, it shuts down right after they log in. The story given by the employee is as follows:
They installed software using an installer they downloaded online
They ran the installed software but it seemed to do nothing
Now every time they bootup and login to their computer, a black command prompt screen quickly opens and closes and their computer shuts down instantly.
See if you can find evidence for the each of these events and retrieve the flag (split into 3 pieces) from the correct logs!
Download the Windows Log file [here](https://challenge-files.picoctf.net/c_verbal_sleep/123d9b79cadb6b44ab6ae912f25bf9cc18498e8addee851e7d349416c7ffc1e1/Windows_Logs.evtx)
>Hint 1: Try to filter the logs with the right event ID

>Hint 2: What could the software have done when it was ran that causes the shutdowns every time the system starts up?

## 6. Bitlocker-2
### Description:
Jacky has learnt about the importance of strong passwords and made sure to encrypt the BitLocker drive with a very long and complex password. We managed to capture the RAM while this drive was opened however. See if you can break through the encryption!
Download the disk image [here](https://challenge-files.picoctf.net/c_verbal_sleep/b22e1ca13c0b82bb85afe5ae162f6ecbdf5b651e364e6a2b57c9ad44ae0b3bfd/bitlocker-2.dd) and the RAM dump [here](https://challenge-files.picoctf.net/c_verbal_sleep/b22e1ca13c0b82bb85afe5ae162f6ecbdf5b651e364e6a2b57c9ad44ae0b3bfd/memdump.mem.gz)

```python=
┌──(kali㉿kali)-[~/Desktop/volatility_2.6_lin64]
└─$ ./vol -f ../memdump.mem imageinfo
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win10x64_19041
                     AS Layer1 : SkipDuplicatesAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/kali/Desktop/memdump.mem)
                      PAE type : No PAE
                           DTB : 0x1ad000L
                          KDBG : 0xf8006340eb20L
          Number of Processors : 2
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0xfffff800617eb000L
                KPCR for CPU 1 : 0xffffb98179e67000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2025-03-10 02:58:56 UTC+0000
     Image local date and time : 2025-03-09 22:58:56 -0400
```

>Hint: Try using a volatility plugin


>Bài này thì mình chịu thật, có imageinfo ra profile, pstree, netscan cũng không trả về kết quả gì, clone plugin `bitlocker for volatility` từ [github](https://github.com/breppo/Volatility-BitLocker.git) nhờ vào hint và tìm được mã FVEK như github hướng dẫn

```python= 
[FVEK] FVEK:
65b8064ec7acea96726aa18d294213176fd513a62a95c80720648f0590211364
```
> mount file disk dùng `dislocker` nhưng mà lại không giải mã khóa được

```python=
┌──(kali㉿kali)-[~/Desktop]
└─$ dislocker -r -V bitlocker-2.dd -k fvek.key -- /Desktop/bitlocker2/
Mon Mar 17 19:24:58 2025 [CRITICAL] None of the provided decryption mean is decrypting the keys. Abort.
Mon Mar 17 19:24:58 2025 [CRITICAL] Unable to grab VMK or FVEK. Abort.
```

>Đến đây thì chịu, lúc sau vào nghịch nghịch strings thì wow =)))))))))))))))))))))

```python=
┌──(kali㉿kali)-[~/Desktop]
└─$ strings memdump.mem| grep -i picoctf
picoCTF{B1tl0ck3r_dr1v3_d3crypt3d_9029ae5b}
picoCTF{B1tl0ck3r_dr1v3_d3crypt3d_9029ae5b}
picoCTF{B1tl0ck3r_dr1v3_d3crypt3d_9029ae5b}

```

flag: `picoCTF{B1tl0ck3r_dr1v3_d3crypt3d_9029ae5b}
`





















