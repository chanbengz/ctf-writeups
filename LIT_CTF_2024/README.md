# LITCTF 2024 Personal Writeup

> 虾饺歇了一周，但恰好又比较闲，于是跟[学弟](https://blog.xciphand.icu/2024/08/12/LITCTF-2024/#Web-%E7%BD%91%E7%AB%99)开了个COMP4SS车队打个高中生比赛玩玩，然后又被带飞了。
>
> 学弟ak了web，半ak了misc（剩一道kuwahara写代码题，工作量比较大），本菜只能捡学弟不会的crypto来ak（
> 
> 我俩都不会pwn，于是pwn爆零

## Web

### anti-inspect

直接打开会崩，所以就curl
```bash
curl http://litctf.org:31779/ | grep LITCTF{
```

## Crypto

### simple otp

```diff
import random

encoded_with_xor = b'\x81Nx\x9b\xea)\xe4\x11\xc5 e\xbb\xcdR\xb7\x8f:\xf8\x8bJ\x15\x0e.n\\-/4\x91\xdcN\x8a'

random.seed(0)
key = random.randbytes(32)

+ flag = bytes([a ^ b for a, b in zip(encoded_with_xor, key)])
+ print(flag)

```

### privatekey

低解密指数，维纳攻击

```python
import gmpy2
from Crypto.Util.number import long_to_bytes

def transform(x,y):
    res = []
    while y:
        res.append(x // y)
        x, y = y, x % y
    return res
    
def continued_fraction(sub_res):
    numerator, denominator = 1, 0
    for i in sub_res[::-1]:
        denominator, numerator = numerator, i * numerator + denominator
    return denominator, numerator
    
def sub_fraction(x, y):
    res = transform(x, y)
    res = list(map(continued_fraction, (res[0:i] for i in range(1, len(res)))))
    return res

def get_pq(a, b, c):
    par = gmpy2.isqrt(b * b - 4 * a * c)
    x1, x2 = (-b + par) // (2 * a), (-b - par) // (2 * a)
    return x1, x2

def wienerAttack(e, n):
    for (d, k) in sub_fraction(e, n):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        
        phi = (e * d - 1) // k
        px, qy = get_pq(1, n - phi + 1, n)
        if px * qy == n:
            p, q = abs(int(px)), abs(int(qy))
            d = gmpy2.invert(e, (p - 1) * (q - 1))
            return d
    print("Failed to find d")

N = 91222155440553152389498614260050699731763350575147080767270489977917091931170943138928885120658877746247611632809405330094823541534217244038578699660880006339704989092479659053257803665271330929925869501196563443668981397902668090043639708667461870466802555861441754587186218972034248949207279990970777750209
e = 89367874380527493290104721678355794851752244712307964470391711606074727267038562743027846335233189217972523295913276633530423913558009009304519822798850828058341163149186400703842247356763254163467344158854476953789177826969005741218604103441014310747381924897883873667049874536894418991242502458035490144319
c = 71713040895862900826227958162735654909383845445237320223905265447935484166586100020297922365470898490364132661022898730819952219842679884422062319998678974747389086806470313146322055888525887658138813737156642494577963249790227961555514310838370972597205191372072037773173143170516757649991406773514836843206

d = wienerAttack(e, N)
m = pow(c, d, N)

print(long_to_bytes(m))
```

### pope shuffle

给了一个UTF-8的文本，提示说是凯撒密码，然后复制粘贴到一个文本再`read(file, encoding='utf-8')`打开

```python
>>> ord(enc[0])
2100
>>> ord(enc[1])
2097
>>> ord('L')
76
>>> ord('I')
73
```

显然offset是2100-76=2024，然后就结束了。

### Symmetric RSA

> 人老变蠢了。。。抓了个数批zz过来就解出来了

题目
```python
from Crypto.Util.number import getPrime, bytes_to_long as btl, long_to_bytes as ltb

p = getPrime(1024)
q = getPrime(1024)

n = p * q
e = p

with open("flag.txt", "rb") as f:
	PT = btl(f.read())

CT = pow(PT, e, n)
print(f"{CT = }")

for _ in range(4):
	CT = pow(int(input("Plaintext: ")), e, n)
	print(f"{CT = }")
```

$(n,e)$都不给，然后只知道$e=p$，一直在想这个肯定有什么特殊性质，还给了4次选择明文。一开始没发现选择明文可以直接输入任意数字，负数也可以，然后就用

$$ n = ((-1)^p \mod n) + 1 $$

还原$n$，接着查询2, 3, 5 然后费马小定理有

$$ C_2 = 2^p \equiv 2 \mod p $$
$$ C_3 = 3^p \equiv 3 \mod p $$
$$ C_5 = 5^p \equiv 5 \mod p $$

于是显然

$$ p = \gcd(C_2 - 2, C_3 - 3, C_5 - 5, n) $$

剩下就经典RSA解密了

```python
from pwn import *
from Crypto.Util.number import long_to_bytes, GCD

p = remote('litctf.org', 31783)
msg = p.recv().decode()
p.sendline(b'-1')
msg += p.recv().decode()
p.sendline(b'2')
msg += p.recv().decode()
p.sendline(b'3')
msg += p.recv().decode()
p.sendline(b'5')
msg += p.recv().decode()
ciphers = []

for i in msg.split('\n'):
    ciphers.append(i.split('= ')[-1])

n = int(ciphers[1]) + 1
p = n
for i, remainder in enumerate((2, 3, 5)):
    p = GCD(p, int(ciphers[i + 2]) - remainder)

q = n // p
assert p * q == n

phi = (p - 1) * (q - 1)
d = pow(p, -1, phi)
m = pow(int(ciphers[0]), d, n)

print(long_to_bytes(m).decode(), end="")

```

### Truly Symmetric RSA

题目
```python
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl, getPrime

p = getPrime(1536)
q = getPrime(1024)

n = p*q

e = p

with open("flag.txt", "rb") as f:
	PT = f.read()

CT = pow(btl(PT), e, n)
print(f"{len(PT) = }")
print(f"{CT = }")
print(f"{n = }")
```

$p$ 比 $q$ 长512 bits，而且$e = p$，刚好sage自带，直接Coppersmith秒了

```python
from Crypto.Util.number import long_to_bytes

CT = 155493050716775929746785618157278421579720146882532893558466000717535926046092909584621507923553076649095497514130410050189555400358836998046081044415327506184740691954567311107014762610207180244423796639730694535767800541494145360577247063247119137256320461545818441676395182342388510060086729252654537845527572702464327741896730162340787947095811174459024431128743731633252208758986678350296534304083983866503070491947276444303695911718996791195956784045648557648959632902090924578632023471001254664039074367122198667591056089131284405036814647516681592384332538556252346304161289579455924108267311841638064619876494634608529368113300787897715026001565834469335741541960401988282636487460784948272367823992564019029521793367540589624327395326260393508859657691047658164
n = 237028545680596368677333357016590396778603231329606312133319254098208733503417614163018471600330539852278535558781335757092454348478277895444998391420951836414083931929543660193620339231857954511774305801482082186060819705746991373929339870834618962559270938577414515824433025347138433034154976346514196324140384652533471142168980983566738172498838845701175448130178229109792689495258819665948424614638218965001369917045965392087331282821560168428430483072251150471592683310976699404275393436993044069660277993965385069016086918288886820961158988512818677400870731542293709336997391721506341477144186272759517750420810063402971894683733280622802221309851227693291273838240078935620506525062275632158136289150493496782922917552121218970809807935684534511493363951811373931

PR.<x> = PolynomialRing(Zmod(n))
flag = (x - CT).small_roots(X=256**62, beta=0.5)[0]
print(long_to_bytes(int(flag)))
```

## Reverse

### Burger Reviewer

大模拟逆向，直接人肉解
```python
import jpype

flag = 'LITCTF{' + '*' * 34 + '}'
assert len(flag) == 42

flag_list = list(flag)

flag_list[13] = flag_list[19] = flag_list[29] = flag_list[39] = '_'
flag_list[17] = chr(95)
flag_list[26] = chr(190 - ord('_'))
flag_list[34] = chr(95)

meat = ['n', 'w', 'y', 'h', 't', 'f', 'i', 'a', 'i']
dif = [4, 2, 2, 2, 1, 2, 1, 3, 3]
m = 41

for i in range(len(meat)):
    m -= dif[i]
    flag_list[m] = meat[i]

veg1 = [10, 12, 15, 22, 23, 25, 32, 36, 38, 40]
veg = [0] * 10

veg[9] = 2
veg[8] = 7
veg[7] = 4
veg[6] = 3
veg[5] = 5
veg[4] = 2
veg[3] = 2
veg[2] = 4
veg[1] = 5
veg[0] = 9

for i in range(len(veg)):
    flag_list[veg1[i]] = str(veg[i])

sauce = ['b', 'p', 'u', 'b', 'r', 'n', 'r', 'c']
a = 7
b = 20
i = 0

while a < b:
    flag_list[a] = sauce[i]
    flag_list[b] = sauce[i + 1]
    a += 1
    b -= 1
    i += 2
    while not flag_list[a].isalpha() and not flag_list[a] == '*':
        a += 1
    while not flag_list[b].isalpha() and not flag_list[b] == '*':
        b -= 1

print(''.join(flag_list))
```
