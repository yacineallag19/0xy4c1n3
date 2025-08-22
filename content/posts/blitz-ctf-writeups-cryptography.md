---
date: '2025-07-25T09:52:05+01:00'
draft: false
title: 'Blitz CTF 2025 writeups (Cryptography)'
tags: ["CTF","Cryptography", "writeups", "Cyber Security","Blitz CTF"]
categories: ["CTF Writeups"]
---


----------


![Challenge Image](https://ctftime.org/media/cache/7b/b5/7bb5df82fc9891185faf9588ea436b91.png)

### **Introduction**
I will be covering here writeups to challenges I was able to solve in the BlitzCTF 2025:
- Custom RSA ( cryptography )
- Custom RSA Revenge ( cryptography )
- Fiboz ( cryptography )
- maffs ( cryptography )

----------
### **Custom RSA**

We were given 2 files:

-   [Custom_RSA.py](https://drive.google.com/file/d/18sDZ_AOuBk6FMQotDdLhfFNOpApBxXvs/view?usp=drive_link)
-   [out_4.txt](https://drive.google.com/file/d/1yxNTX9WgDRYZx99nn-TURhMn06fXXmz_/view?usp=drive_link)

#### Initial Analysis
Let's start by reading the source code and understanding what each part does:
```python
p = getPrime(256)  
q = getPrime(256)  
x = getPrime(128)  
y = getPrime(128)  
z = getPrime(128)
```
This generates 5 primes: `p`, `q`, `x`, `y` and `z`. The information we can keep in mind is the fact that `x`, `y` and `z` are 128 bits which makes the product of each 2 of them easy to factor.

Then we have: 
```python
e = x*y*z
n = p*q*y
hint1 = p % x
hint2 = p % z
```
This sets the `exponent` to the product of `x`, `y` and `z`, as well as the `modulus` to the product of `p`, `q` and `y`. We notice that `y` is a common factor, and since both `e` and `n` are products to **prime facotrs**, we can conclude that: `y = GCD(n,e)`.
Last, 2 hint values are computed: `hint1 = p % x` and `hint2 = p % z`.
Finally, the flag is encrypted, and we are given the values of `e`, `n`, `hint1`, `hint2` and `c`.

#### Exploit Steps
1. Recover `y` by computing: `y = GCD(n,e)`.
2. Calculate `x*z = e // y` then factor the value in order to get x and z (You can factor using a script or using factordb).
3. Recover `temp = p mod (x*z)`from `hint1` and `hint2` using CRT, then brute force all values `p = k * (x * z) + temp` till a value is a factor of `n`.
4. Recover `q`, calculate `d` and decrypt the flag.

#### Python Solver
```python
from sympy import gcd
from Crypto.Util.number import long_to_bytes

hint1 = 154888122383146971967744398191123189212
hint2 = 130654136341446094800376989317102537325
n = 1291778230841963634710522186531131140292748304311790700929719174642140386189828346122801056721461179519840234314280632436994655344881023892312594913853574461748121277453328656446109784054563731
e = 9397905637403387422411461938505089525132522490010480161341814566119369497062528168320590767152928258571447916140517
c = 482782367816881259357312883356702175242817718119063880833819462767226937212873552015335218158868462980872863563953024168114906381978834311555560455076311389674805493391941801398577027462103318

# Step 1: calculate y
y = int(gcd(n, e))

# Step 2: get x and z by factoring x*z
xz = e // y
x = 205985756524450894105569840071389752521
z = 212007435030018912792096086712981924541

# Step 3: finding p mod x*z using CRT
def chinese_remainder(h, m1, h2, m2):
    def inv(a, m):
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            a, m = m, a % m
            x0, x1 = x1 - q * x0, x0
        return x1 % m0
    M = m1 * m2
    return (h * m2 * inv(m2, m1) + h2 * m1 * inv(m1, m2)) % M, M

p0, M = chinese_remainder(hint1, x, hint2, z)

# Step 4: brute forcing till we get the correct p values
for k in range(0, 5):
    p = p0 + k * M
    if n % p != 0:
        continue
    # Step 5: Calculating q
    q = n // ( p * y )
    # Step 6: compute private exponent d and decrypt
    phi = int((p-1) * (q-1) * (y-1))
    try:
        d = pow(e, -1, phi)
    except ValueError:
        continue
    m = pow(c, d, n)
    pt = long_to_bytes(m)
    if pt.startswith(b"Blitz"):
        print(pt)
        break
else:
    print("no candidate found")
```
There goes the flag: **Blitz{H0w_D4r3_y0u_br34k_My_RSA_Ag41n!!!}**

---
### **Custom RSA Revenge**
We were given 2 files:
- [crypto1.py](https://drive.google.com/file/d/1mvOOqhcPuSNTIAlK-OoUR_PPynuBuf_W/view?usp=drive_link)
- [crypto1_out.txt](https://drive.google.com/file/d/1SbOepVzlhRdjocS0p5YC2subxysT6Zh2/view?usp=drive_link)

#### Initial Analysis
Let's start by reading the source code and understanding what each part does:
```python
p = getPrime(150)
q = getPrime(150)
e = getPrime(128)
n = p*q
```
So far seems like a usual RSA setup, let's continue:
```python
mod_phi = (p-1)*(q-1)*(e-1)
d = pow(e, -1, mod_phi)
 
print(mod_phi)
print(n)
c = pow(bytes_to_long(m), e, n)
print(c)
```
Now we can spot the issue, `mod_phi` is easy to factor in no time, if we manage to factor it we can easily recover `e`, `p` and `q`.

I used this tool: [Factorization online tool](https://www.alpertron.com.ar/ECM.HTM).
It gave many factors but we will use this so we don't have to keep copying pasting:
```381 679521 901481 226602 014060 495892 168161 810654 344421 566396 411258 375972 593287 031851 626446 898065 545609 421743 932153 327689 119440 405912 (129 digits) = 23 × 32 × 67 × 673 × 3181 × 252401 × 23 896409 × 145 028189 × 79 561224 974873 × 308 026511 504069 × 4509 599821 882817 × 9907 158782 085681 344183 × 38 588687 064594 940957 905160 665643 (32 digits)```.
Using these prime factors, we will generate all possible factors, and for each factor `f` we will check if `f+1` divides `n`, then we would have the values of `p`,`q` and `e`, and we can just decrypt then.

#### Python Solver
```python
from sympy import Integer
from itertools import product
from Crypto.Util.number import long_to_bytes

# Factorization result of mod_phi
factors = {
    2: 5,
    3: 1,
    23: 2,
    32: 1,
    67: 1,
    673: 1,
    3181: 1,
    252401: 1,
    23896409: 1,
    145028189: 1,
    79561224974873: 1,
    308026511504069: 1,
    4509599821882817: 1,
    9907158782085681344183: 1,
    38588687064594940957905160665643: 1,
}

# Generate all divisors of mod_phi
def get_divisors(factors):
    primes = list(factors.items())
    exponents = [range(e + 1) for _, e in primes]
    for powers in product(*exponents):
        divisor = Integer(1)
        for (base, _), power in zip(primes, powers):
            divisor *= base ** power
        yield divisor

n = 1236102848705753437579242450812782858653671889829265508760569425093229541662967763302228061
c = 337624956533508120294617117960499986227311117648449203609049153277315646351029821010820258
mod_phi = 381679521901481226602014060495892168161810654344421566396411258375972593287031851626446898065545609421743932153327689119440405912

# Step 1: generate all divisors of mod_phi
divisors = sorted(get_divisors(factors))

print(f"[*] Total divisors: {len(divisors)}")

# Step 2: check if (d+1) divides n (this reveals p or q)
for d in divisors:
    if n % (d + 1) == 0:
        p = d + 1
        q = n // p
        print(f"[+] Found factors! p = {p}, q = {q}")

        # Step 3: recover e
        phi = (p - 1) * (q - 1)
        e = mod_phi // phi + 1
        print(f"[+] Recovered e = {e}")

        # Step 4: compute private exponent d and decrypt
        d_priv = pow(e, -1, phi)
        m = pow(c, d_priv, n)
        print("[+] Decrypted flag:", long_to_bytes(m))
        break
```
There goes the flag: **Blitz{Cust0m_RSA_OMGGG}**

---
### **Fiboz**
We were given 2 files:

- [Fiboz.py](https://drive.google.com/file/d/1kZUISefyYOQoVUKQUX-BWH_R00-B4T2J/view?usp=drive_link)
- [output.enc](https://drive.google.com/file/d/11Fhf4bi6Z6cMdD4Yj_jAmvv7s3pSirD8/view?usp=drive_link)

#### Initial Analysis
Let's start by reading the source code and understanding what each part does:
```python
def x7a3(n):
    s = 0
    while n != 1:
        n = n // 2 if n % 2 == 0 else 3 * n + 1
        s += 1
    return s
```
This function implements the Collatz sequence, which is a mathematical process that repeatedly transforms a number until it becomes 1, and it returns how many steps the process took.
Then we have: 
```python
def y4f2(l, a=1, b=1):
    r = [a, b]
    for _ in range(l - 2):
        r.append(r[-1] + r[-2])
    return r
```
This function generates a Fibonacci-like sequence, which is a list of numbers where each new number is the sum of the previous two, and it returns the sequence of length `l` starting with `a` and `b`.
Finally, the last function is: 
```python
def z9k1(s, k):
    return bytes(ord(c) ^ (k[i % len(k)] % 256) for i, c in enumerate(s))
```
This function takes a string `s` and a key `k`, and returns a `bytes` object where each character in `s` is XORed with the corresponding (cyclic) element of `k` modulo 256.

Now it is time to check what the main function is doing:
```python
def main():
    print("Challenge ready!")
    try:
        l = int(input("Enter length: "))
        a = int(input("First seed [1]: ") or 1)
        b = int(input("Second seed [1]: ") or 1)
    except:
        print("Error")
        sys.exit(1)

    f = y4f2(l, a, b)
    c = [x7a3(n) for n in f]
    t = input("\nInput text: ")
    if not t:
        t = "Blitz{example_flag}"

    e = z9k1(t, c)
    with open('output.enc', 'wb') as file:
        file.write(e)
    print("Output written to output.enc (hex format)")
```
The `main()` function first takes user input for `l`, `a`, and `b`, and passes them to `y4f2()` to generate a list of numbers, storing the result in `f`.  
Then it applies `x7a3()` to each element of `f`, storing the transformed list in `c`.  
Finally, it takes the flag, encrypts it with `z9k1(t, c)` and saves the result as `output.enc`.

#### Identifying The Vulnerability
The vulnerability here is that the flag format (Blitz{...}) is known, the first key bytes can be recovered, making it easy to brute force the `a` and `b` values and decrypt the message.

#### Exploitation Steps

1.   Use the known prefix `Blitz{` to recover the first key bytes by XORing with the ciphertext.
2.   Precompute Collatz step counts and map step values back to possible numbers.
3.   From the first key bytes, get candidate values for `a` and `b`.
4.   Check which `(a,b)` pairs fit the Fibonacci-like pattern with the next key bytes.
5.   For valid `(a,b)`, rebuild the full key, decrypt the ciphertext, and check the result.
6.   If the text starts with `Blitz{`, that’s the flag.

#### Python Solver
```python
import sys
from collections import defaultdict

def x7a3(n):
    steps = 0
    while n != 1:
        n = n // 2 if n % 2 == 0 else 3 * n + 1
        steps += 1
    return steps

def precompute_x7a3(max_n):
    table = [0] * (max_n + 1)
    for n in range(2, max_n + 1):
        x, steps = n, 0
        while x != 1:
            x = x // 2 if x % 2 == 0 else 3 * x + 1
            steps += 1
            if x > max_n:
                break
        table[n] = steps
    return table

def build_k_to_n(x7a3_table):
    k_to_n = defaultdict(list)
    for n, k in enumerate(x7a3_table):
        k_to_n[k].append(n)
    return k_to_n

def y4f2(length, a, b):
    seq = [a, b]
    for _ in range(length - 2):
        seq.append(seq[-1] + seq[-2])
    return seq

def decrypt(ciphertext, key):
    return bytes([ciphertext[i] ^ (key[i % len(key)] % 256) for i in range(len(ciphertext))])

def recover_a_b(ciphertext, plaintext_start, max_n=10000000):

    # Step 1
    k = [plaintext_start[i] ^ ciphertext[i] for i in range(len(plaintext_start))]
    print(f"Recovered key bytes: {k}")

    # Step 2
    x7a3_table = precompute_x7a3(max_n)
    k_to_n = build_k_to_n(x7a3_table)

    # Step 3
    for a in k_to_n.get(k[0], []):
        for b in k_to_n.get(k[1], []):

            # Step 4
            if (a + b) > max_n or x7a3_table[a + b] != k[2]:
                continue
            if (a + 2 * b) > max_n or x7a3_table[a + 2 * b] != k[3]:
                continue
            if (2 * a + 3 * b) > max_n or x7a3_table[2 * a + 3 * b] != k[4]:
                continue
            if (3 * a + 5 * b) > max_n or x7a3_table[3 * a + 5 * b] != k[5]:
                continue

            # Step 5
            f = y4f2(len(ciphertext), a, b)
            c = [x7a3(n) for n in f]
            decrypted = decrypt(ciphertext, c)
            try:
                decrypted_text = decrypted.decode('ascii')
                # Step 6
                if decrypted_text.startswith("Blitz{"):
                    print(f"a={a}, b={b}")
                    print(decrypted_text)
                    sys.exit(0)
            except UnicodeDecodeError:
                continue

if __name__ == "__main__":
    with open('output.enc', 'rb') as f:
        ciphertext = f.read()

    plaintext_start = b"Blitz{"
    if len(ciphertext) < len(plaintext_start):
        print("Ciphertext too short!")
        sys.exit(1)

    recover_a_b(ciphertext, plaintext_start)
```
The output:
```bash
Recovered key bytes: [180, 129, 246, 102, 131, 186]
a=121393, b=196418
Blitz{So_You_Have_Studied_Fibonacci_And_Collatz_Conjecture_Now?}
```
There goes the flag: **Blitz{So_You_Have_Studied_Fibonacci_And_Collatz_Conjecture_Now?}**

---
### **Muffs**

We were given 34 files:
- [Files link](https://drive.google.com/drive/folders/1mRSxuarJHQ_aouUPjQUj7ltfOPYIwVuB?usp=drive_link)

Each file contained a set of points `(x,y)`that were sampled from an unknown polynomial. The idea was that the coefficients of this polynomial were everything we needed. By fitting a polynomial to the points in each file, we could recover its coefficients, and from there compute its derivatives at `x=0`. Since the `i-th` derivative at zero is simply `a⋅i!`, where `a`​ is the `i-th`coefficient, one of these derivatives in each file turned out to be very close to an integer within the printable ASCII range. That integer represented a character of the flag. By repeating this process for all 34 files, we extracted one character from each and combined them to reconstruct the entire flag.

#### Python Solver
```python
import numpy as np
import glob
from math import factorial

def is_printable_ascii(c):
    return 32 <= c <= 126

def decode_flag():
    files = sorted(glob.glob("f*.txt"), key=lambda fn: int(fn[1:-4]))
    chars = []

    for fn in files:
        data = np.loadtxt(fn)
        x, y = data[:, 0], data[:, 1]

        X = np.column_stack([x**i for i in range(9)])
        coeffs, *_ = np.linalg.lstsq(X, y, rcond=None)

        best_char = '?'
        best_error = float('inf')
        best_info = None

        for i, a in enumerate(coeffs):
            val = a * factorial(i)
            rounded = round(val)
            error = abs(val - rounded)

            if is_printable_ascii(rounded) and error < best_error:
                best_char = chr(rounded)
                best_error = error
                best_info = (i, a, val, rounded, error)

        if best_char == '?':
            print(f"\n[!] Could not determine char for {fn}")
            for i, a in enumerate(coeffs):
                val = a * factorial(i)
                rounded = round(val)
                error = abs(val - rounded)
                print(f"  a{i} = {a:.8f}, a{i} * {i}! = {val:.2f}, round = {rounded}, error = {error:.2e}")
        else:
            n, a, val, r, err = best_info
        chars.append(best_char)

    print("".join(chars))

if __name__ == "__main__":
    decode_flag()
```
There goes the flag: **Blitz{C4lcu1us_G0eS_Brrrrrrrrr!!!}**

--- 
![Primeagen](https://media1.tenor.com/m/hYU0XdvEzmAAAAAC/theprimeagen-primeagen.gif)

That's all for this blog, thank you for reading.