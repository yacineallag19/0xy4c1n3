---
date: '2025-08-08T09:52:05+01:00'
draft: false
title: 'WorldWide CTF “Faulty Curve” Challenge Writeup (Cryptography)'
tags: ["CTF","Cryptography", "writeups", "ECC", "Cyber Security","WorldWide CTF"]
categories: ["CTF Writeups"]
---


----------


![Challenge Image](https://cdn-images-1.medium.com/max/1200/1*CiYOElU76D1vhNLUu1ItXg.jpeg)

## WorldWide CTF "Faulty Curve" Challenge Writeup (Cryptography)

### **Challenge Overview**

-   CTF: WorldWide CTF 2025
-   Challenge: Faulty Curve
-   Category: Cryptography
-   Points: 436
-   Author: Warri
-   Description:

> **ECDLP is so fun to write! Except sagemath seems to break for mine upon initialisation, guess I'll have to do everything in python…** **Note: The sagemath error in question can be traced in the latest version of sage**

-   Source Code: [chall.py](https://pastebin.com/GEHiBpgb)

----------

### **Introduction**

This write-up details the solution to the **Faulty Curve** cryptography challenge from **WorldWideCTF**, which exploits the **curve's singularity** to decrypt **ECC-based ciphers**. We demonstrate how the singular elliptic curve vulnerability allows decryption by reducing the **discrete logarithm problem** to a **trivial** linear equation. This write-up will be beginner-friendly and explain everything in detail. We'll start with how elliptic curves work, then walk through how our team solved this challenge.

----------

### **Introduction To Elliptic Curves**

Cryptography's history is divided into **classical** and **modern** eras, with the shift marked in 1977 by the introduction of **RSA** and **Diffie-Hellman**. These algorithms were groundbreaking as they enabled secure communication **without a shared secret**, relying on number theory rather than secret codebooks for security. Modern cryptography is based on the idea that encryption keys can be public while decryption keys remain private. These systems are called public key cryptographic systems.

After RSA and Diffie-Hellman, researchers sought other math-based cryptographic methods, leading to elliptic curve cryptography in 1985, based on a lesser-known area of mathematics.

An elliptic curve is a set of points that satisfy an equation of the form:  
**y² = x³ + ax + b**, which will make the set of points give a graph similar to this:

![Elliptic Curve Graph](https://cdn-images-1.medium.com/max/800/1*hhP0Ur8c6bN8XnTHPkCr7Q.png)

_An Elliptic Curve with the equation: **y² = x³ + 0.5x + 4**_

#### Elliptic Curves Properties:

-   The curve is symmetric about the x-axis, meaning if a point `(x, y)` is on the curve, then `(x, -y)` is also on the curve.
-   Any non-vertical line drawn through the curve will intersect it at most three points.
-   Take any two points A and B on the curve and draw a line through them, it will intersect the curve at exactly one more point C, reflecting this point over the x-axis gives -C (either straight up if it's below the x-axis or straight down if it's above the x-axis to the other side of the curve). The transformation from A,B to -C is often noted as **dot**: **A dot B = -C**
-   We can also do: A dot A which will give us a point B, and that leads us to this conclusion:

> _if we do: A dot A = B then A dot B = C and we repeat the process n times till we get a point P, it is very difficult to tell what value is n using only the starting point A and the final point P. This problem is called the discrete logarithm problem_

Although these properties hold for all real numbers, in cryptography we restrict the calculations to integers within a fixed range, similar to RSA, calculations wrap around a prime number, forming a _prime curve_ with strong cryptographic properties, which will give this new formula: **y² = x³ + ax + b (mod p)** where p is a prime (preferably **large**), this formula is the base of Elliptic Curves Cryptography

Given that, if we want to encrypt information using this cryptosystem, we will need:

-   A large prime **p (known to both sender and receiver)**
-   Curve parameters **a** & **b (known to both sender and receiver)**
-   A **base point G** (must be on the curve) **(known to both sender and receiver)**
-   A random large prime **q**: **The private key (only receiver knows it)**

The public key **Q** will be: G dotting itself **q times (known to both sender and receiver)**

Given a point M (there are many ways to map a message to a point M but it shouldn't be our concern for now), these are the steps used to encrypt a message and get it back:

1.  Sender picks a random number k ≤ p.
2.  Sender computes: C1 = kG and C2 = m+kQ.
3.  Sender sends (C1,C2).
4.  Receiver computes: qC1 = q(kG) = k(qG) = kQ.
5.  Receiver recovers the message M = C2​−dC1​=M+kQ−kQ=M.
6.  Receiver should map back M to m.

Now that we have an idea of how Elliptic Curves Cryptography works, we can move to our challenge writeup.

----------

### **Initial Analysis**

We start by reading the source code for this challenge, first there are 2 functions **add** and **mul**:

```python
def add(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return None
    if x1 == x2:
        m = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)

def mul(k, P, a, p):
    R0 = None
    R1 = P
    for bit in bin(k)[2:]:
        if bit == '0':
            R1 = add(R0, R1, a, p)
            R0 = add(R0, R0, a, p)
        else:
            R0 = add(R0, R1, a, p)
            R1 = add(R1, R1, a, p)
    return R0

```

The two functions implement point addition and scalar multiplication on elliptic curves over a finite field. While they are functionally correct for standard use cases, the implementations are not optimized for constant-time execution, which may expose them to timing-based side-channel attacks. These potential vulnerabilities should be considered in future stages of our analysis when reviewing the rest of the source code.

Then we have this part:

```python
flag = int.from_bytes(b"wwf{???????????????????????????}")

from secret import p, a, b, G
# EllipticCurve(GF(p), [a,b]) in sage gives an error for some reason :sob:
# Some error in /src/sage/schemes/elliptic_curves but i'm too nub to figure out why :sob: :sob:
Gx = G[0]
Qx = mul(flag, G, a, p)[0]
print(f'{p = }')
print(f'{a = }')
print(f'{Gx = }')
print(f'{Qx = }')
"""
p = 3059506932006842768669313045979965122802573567548630439761719809964279577239571933
a = 2448848303492708630919982332575904911263442803797664768836842024937962142592572096
Gx = 3
Qx = 1461547606525901279892022258912247705593987307619875233742411837094451720970084133
"""

```

First, it maps the flag bytes into an integer. Then, it imports the prime **p**, the curve parameters **a** and **b**, and the base point **G**.  
Afterward, we notice a sort of indication of an error that occurred:

```python
# EllipticCurve(GF(p), [a,b]) in sage gives an error for some reason :sob:
# Some error in /src/sage/schemes/elliptic_curves but i'm too nub to figure out why :sob: :sob:

```

While the author claimed he didn't want to debug it, we will definitely inspect it. Let's try googling: `EllipticCurve(GF(p), [a, b])` errors and see what comes up:

![Google Search Results](https://cdn-images-1.medium.com/max/800/1*zy-_KHxPpU1gCfRbT6uNKg.png)

According to Gemini, the error must be due to one of the following reasons:

-   Incorrect curve parameters **a** and **b**: not likely in this case.
-   The curve is **singular**, meaning it is vulnerable and satisfies the singularity condition:

![Singularity Condition](https://cdn-images-1.medium.com/max/800/1*WcUR52K4xjmOs1HyHf8xyA.png)

-   p is not a prime, **but this is not true.**

Therefore, we can assume for now that the error stems from the curve being singular, which we will discuss further after completing our initial analysis.

Now, let's continue analyzing the rest of the source code:

```python
Gx = G[0]
Qx = mul(flag, G, a, p)[0]
print(f'{p = }')
print(f'{a = }')
print(f'{Gx = }')
print(f'{Qx = }')

```

Here, `Gx` is the x-coordinate of the base point **G**, and `Qx` is the x-coordinate of **Q=flag⋅G**, in other words, **G** was multiplied (dotted) by `flag` to obtain **Q**.

The values we have are **p**, **a**, **Gx** and **Qx**, we don't have **b**. While we don't have the value of **b**, we must remember that the curve is assumed to be **singular**, which means it satisfies the following condition:

![Singularity Formula](https://cdn-images-1.medium.com/max/800/1*WcUR52K4xjmOs1HyHf8xyA.png)

Given that we can calculate the b values that will verify the equation.

----------

### **Singular Curves**

A **singular** curve is a curve that has a null discriminant, thus the polynomial **x³ + ax + b** has a double or triple root **r**. This gives us one of the 2 equations here: **x³ + ax + b = (x-r)³** or **x³ + ax + b = (x-r)²(x-k)**.

Using a change of variable t = x + r we get:

**x³ + ax + b = t³** or **x³ + ax + b = t²(x-k)**

For the first case it is trivial to solve the discrete logarithm problem since it will be just a _simple division_ in a finite field, and for the 2nd case, it is not that trivial but it is still much faster than the usual discrete logarithm problem since it becomes a _finite-field logarithm_.

With that said, the overall steps to solve the challenge became clear:

1.  Calculate b values that will satisfy the equation.
2.  Solve the _discrete logarithm_: **Q = flag.G**.
3.  Map the flag back to an integer.

----------

### **Step 1: Solving the equation for b**

To solve the equation we must follow these steps:

![Formula Steps](https://cdn-images-1.medium.com/max/800/1*QZ_nrG8VBVcEFYnvprsKAQ.png)

And here goes the sage implementation:

```python
# Find possible b values (that make the curve singular)
F = GF(p)
a_cubed = F(a)^3
rhs = (-4 * a_cubed) * F(27)^(-1)
b_solutions = rhs.sqrt(all=True)
print(f"Possible values for b: {b_solutions}")

```

This gave the following output:

```
Possible values for b: [824668140588526362183895500628724475752920839323887328536605261185064403017929521, 2234838791418316406485417545351240647049652728224743111225114548779215174221642412]

```

----------

### **Step 2: Exploitation**

Now that we have a set of possible **b** values, our next step is to solve the _discrete logarithm problem_, which is known to be significantly easier on this curve due to its singularity.

However, with the values we currently have, it won't be possible to solve the discrete logarithm problem, since we only have the x-coordinate of the base point **G** (i.e., the starting point) and the x-coordinate of the public key **Q** (i.e., the final point). To proceed, we need to find a way to determine the **y-coordinates** of both points.

#### Finding the y-coordinates

We have this equation: **y²=x³ + ax + b**

We can plug in both values Gx, Qx in that equation and we would get:

**RHS1 = Gx³ + aGx + b**

**RHS2 = Qx³ + aQx + b**

If **RHS1** and **RHS2** are quadratic residues in the finite field, then we would get two possible y-coordinates for each of the two points, therefore, two possible points for each.

Here comes the sage implementation for this matter:

```python
# y-coordinates candidates
def get_y_candidates(x, a, b):
    rhs = x^3 + a*x + b
    return [rhs.sqrt(), -rhs.sqrt()] if rhs.is_square() else []

```

Now all we have left to brute force, and solve the DLP, we can write our own exploit for that but we will just use a script that is available online, I used this one: [attack link](https://github.com/elikaski/ECC_Attacks/blob/main/code/ECDH%20Attacks/singular_curve.sage)

Of course we can't use the script as it is, we will have to do some small changes since we will have to brute force **Qy**, **Gy** and **b** values. I don't think it's needed to explain how we will change it since it is obvious.

And this will give us the final script solver:

```python
from Crypto.Util.number import long_to_bytes

# Given values
p = 3059506932006842768669313045979965122802573567548630439761719809964279577239571933
a = 2448848303492708630919982332575904911263442803797664768836842024937962142592572096
Gx = 3
Qx = 1461547606525901279892022258912247705593987307619875233742411837094451720970084133

F = GF(p)
a = F(a)
Gx = F(Gx)
Qx = F(Qx)

# Find possible b values (that make the curve singular)
a_cubed = a^3
rhs = (-4 * a_cubed) * F(27)^(-1)
b_solutions = rhs.sqrt(all=True)

# y candidates
def get_y_candidates(x, a, b):
    rhs = x^3 + a*x + b
    return [rhs.sqrt(), -rhs.sqrt()] if rhs.is_square() else []

def transform(X, Y, t_sqrt):
    return (Y + t_sqrt * X) / (Y - t_sqrt * X)

flag_found = False

for b in b_solutions:
    b = F(b)
    R.<x> = PolynomialRing(F)
    f = x^3 + a*x + b
    roots = f.roots()

    if len(roots) != 2:
        continue

    if roots[0][1] == 2:
        double_root = roots[0][0]
        single_root = roots[1][0]
    else:
        double_root = roots[1][0]
        single_root = roots[0][0]

    t = double_root - single_root
    if not t.is_square():
        continue
    t_sqrt = t.sqrt()

    Gx_shifted = Gx - double_root
    Qx_shifted = Qx - double_root

    Gy_cands = get_y_candidates(Gx, a, b)
    Qy_cands = get_y_candidates(Qx, a, b)

    if not Gy_cands or not Qy_cands:
        continue

    for Gy in Gy_cands:
        for Qy in Qy_cands:
            try:
                g = transform(Gx_shifted, Gy, t_sqrt)
                q = transform(Qx_shifted, Qy, t_sqrt)
                found_key = discrete_log(q, g)
                flag = long_to_bytes(int(found_key)).decode()
                if flag.startswith("wwf{"):
                    flag_found = True
                    break
            except:
                continue
        if flag_found:
            break
    if flag_found:
        break

if flag_found:
    print(f"Valid combination and flag found:\nb = {b}, \nGy = {Gy}, \nQy = {Qy}")
    print(f"flag (integer) : {found_key}")
    print(f"flag (bytes) : {flag}")
else:
    print("No valid flag found.")

```

And here is the output we got:

```
Valid combination and flag found:
b = 824668140588526362183895500628724475752920839323887328536605261185064403017929521,
Gy = 994833171224828611991343781095193268805389877233090654472710276077791906497938223,
Qy = 2851253178006530568087097593123401181441248272753928475619032561616159636799320399
flag (integer) : 54036191088477365498866172985658388918771443974169159843569750176754593636733
flag (bytes) : wwf{sup3rs1ngul4r_1s0m0rph15ms!}

```

There goes the flag: **wwf{sup3rs1ngul4r_1s0m0rph15ms!}**

----------

### References

1.  Singular Curves Problems explained: [The article is here](https://crypto.stackexchange.com/questions/70373/why-are-singular-elliptic-curves-bad-for-crypto)
2.  Singular Curves Exploit: [Exploit is here](https://github.com/elikaski/ECC_Attacks/blob/main/code/ECDH%20Attacks/singular_curve.sage)