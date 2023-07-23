---

tags: crypto, elliptic curve, ecc, smart's attack, Pohlig-Hellman Attack
original_url: https://wstein.org/edu/2010/414/projects/novotney.pdf
version: v0.1.0

---

# Peter Novotney: Weak Curves In Elliptic Curve Cryptography

## 摘要

本文介绍了Pohlig-Hellman attack 和 Smart's attack，并讨论了推荐的 NIST 曲线是如何抵御这种攻击的。

## 1. Elliptic Curves

椭圆曲线的通用定义形式为

$$
E(F) = \lbrace x, y \in F^2 : y^2 + a_1xy + a_3y = x^3 + a_2x^2 + a_4x + a_6 \rbrace  \cup \lbrace \mathcal {O} \rbrace
$$

如果域的特征 > 3， 曲线可以简化为

$$
E(F) = \lbrace x, y \in F^2: y^2 = x^3 + ax + b \rbrace \cup \lbrace \mathcal {O} \rbrace
$$

### 1.1 Group Operation

**+**

$P_1, P_2 \in E(F_p), R = P_1 + P_2$ :

1. 如果 $P_1 = \mathcal {O}, R = P_2$
2. 如果 $x_1 = x_2, y_1 = -y_2, R = \mathcal {O}$
3. 

$$
\begin{align}
&\lambda = \left\lbrace
\begin{array}{rcl}
& \frac{3x_1^2 + a}{2y_1}, & P_1=P_2\\
& \frac{y_2-y_1}{x_2-x_1}, & P_1\neq \pm P_2
\end{array} \right.\\
&R = (\lambda^2 - x_1 -x_2, -\lambda x_3 -v), v = y_1 - \lambda x_1, x_3 = \lambda^2 - x_1 -x_2
\end{align}
$$

椭圆曲线的阶记为 $`\#E(F_p)`$

### 1.2 Choice of Field

素域：

$E(F_p) = \lbrace(x, y): y^2 = x^3 + ax +b,x,y,a,b \in F_p\rbrace\cup\lbrace\mathcal{O}\rbrace$

二进制域:

$E(F_{2^m}) = \lbrace(x, y): y^2 + xy = x^3 + ax^2 +b,x,y,a,b \in F_{2^m}\rbrace\cup\lbrace\mathcal{O}\rbrace$

本文仅讨论素域上的攻击

### 1.3 The Elliptic Curve Discrete Logarithm Problem

椭圆曲线的两点 $Q, P \in E(F_p), Q = kP$ ， 求k, 记作 $k = log_pQ$

最快的算法是  Pohlig-Hellman attack 和 Pollard Rho Algorithm

## 2. Attacks on Weak Curves

$E(F_p)$ 
* 在没有较大的素子群时，受 Pohlig-Hellman attack 影响
* #E(Fp) = p 时，受Smart's attack 影响

### 2.1 Pohlig-Hellman Attack

Pohlig-Hellman attack 将 $E(F_p)$ 上的 ECDLP 问题简化为 素子群 $\langle P_i\rangle$ 上的ECDLP问题。

对椭圆曲线的阶 n 素因子分解，得到 $n=p_1^{e_1} * p_2^{e_2} * \cdots * p_r^{e_r}$ ， 对每个素因子，我们希望找到 $k_i \equiv k \pmod {p_i^{e_i}}$ 

令 $P_i = \frac{n}{p_i^{e_i}}P, Q_i = \frac{n}{p_i^{e_i}}Q$

$Q_i = \frac{n}{p_i^{e_i}}Q = \frac{n}{p_i^{e_i}}(k_iP) = k_i(\frac{n}{p_i^{e_i}}P) = k_iP_i$

由中国剩余定理，即可恢复k。

其中 $k_i$ 的计算还可以进一步简化为 $p_i$进制上的 $k_i = z_0 + z_1p_i + z_2p_i^2 + \cdots + z_{e_i-1}p_i^{e_i-1}$

令 $P_0 = \frac{n}{p_i} P, Q_0 = \frac{n}{p_i}Q$ , $P_0$ 的阶为 $p_i$， 因为 $p_iP_0 = nP$

$Q_0 = \frac{n}{p_i}Q = \frac{n}{p_i}(lP) = l(\frac{n}{p_i}P) = lP_0$

因为 $\langle P_0 \rangle$ 的阶为 $p_i$ , $z_0$ 是 $p_i$ 进制上的第一位数，所以 $lP_0 = z_0P_0 = Q_0$ 。$z_0$ 可以由 $\langle P_0 \rangle$ 上的ECDLP求解。

可以将其扩展至 求解 $\langle P_0 \rangle$ 上的ECDLP $Q_j = z_iP_0$ ， 其中

$Q_j = \frac{n}{p_i^{j+1}}(Q-z_0P - z_1p_iP - z_2p_i^2P - \cdots - z_{j-1}p_i^{j-1}P)$

例如 

$$
\begin{align}
Q_1 &= \frac{n}{p_i^2}(Q-z_0P) \\
&= \frac{n}{p_i^2}P(k_i-z_0) \\
&= P_0\frac{z_1p_i + \cdots}{p_i}\\
&= z_1P_0
\end{align}
$$

实现

```python
def PolligHellman(P,Q):
    zList = list()
    conjList = list()
    rootList = list()
    n = P.order()
    factorList = n.factor()
    for facTuple in factorList:
        P0 = (ZZ(n/facTuple[0]))*P
        conjList.append(0)
        rootList.append(facTuple[0]^facTuple[1])
        for i in range(facTuple[1]):
            Qpart = Q
            for j in range(1,i+1):
                Qpart = Qpart - (zList[j-1]*(facTuple[0]^(j-1))*P)
            Qi = (ZZ(n/(facTuple[0]^(i+1))))*Qpart
        zList.insert(i,discrete_log(Qi,P0,operation='+'))
        conjList[-1] = conjList[-1] + zList[i]*(facTuple[0]^i)
    return crt(conjList,rootList)
```

### 2.2 Smart's Attack where #E(Fp) = p

Smart's attack 描述了一种线性时间内计算 `#E(Fp) = p` 的椭圆曲线上 ECDLP的方法。

换一句话说，椭圆曲线的 trace of Frobenius 为1时，可以利用。`t = p+1+#E(Fp) = 1`。

#### 2.2.1 Lifts and Hensel's Lemma

已知 x 为 $f(X) \equiv 0 \pmod p^s$ 的一个解, 偏导 $f'(x)$ 存在模p上的乘法逆元u, 即存在 u使得 $uf'(x)\equiv 1\pmod p$ ，则 $x' = x - uf'(x)$ 是 $f(X) \equiv 0 \pmod {p^{s+1}}$ 的解。

$x' \equiv x \pmod {p^s}, f(x') \equiv 0 \pmod {p^{s+1}}$

这个求解过程称为lift，在 $f'(r) \equiv 0 \pmod p$ 时， 对r的lift是无法预测的，有时候无lift，有时候又多个lift

**proof**

http://web.archive.org/web/20190613022920/http://www.maths.gla.ac.uk/~ajb/dvi-ps/padicnotes.pdf

**Theorem 1.33 (Hensel’s Lemma: first version).**

令 $f(X) = \Sigma_{k=0}^da_kX^k \in \mathbb Z [X]$ , 假设 $x\in \mathbb Z$ 是 $f \mod {p^s} (s \ge 1)$ 的一个根，f'(x) 存在关于模p的乘法逆元。则有 $f \mod {p^{s+1}}$ 的根 $x' \in \mathbb Z/p^{s+1}$ , 满足 $x' \equiv x \pmod {p^s}$ ,  x' 可由公式计算：

$$
x' \equiv x-uf(x) \pmod {p^{s+1}}, u\in \mathbb Z, uf'(x)\equiv 1 \pmod p
$$

proof:

$$
\begin{align}
& x' = x+tp^s \\
& f(x') \\
=&f(x+tp^s) \\
=&f(x) + f'(x)tp^s + ... \\
\equiv & 0 \pmod {p^{s+1}} \\
&\Leftrightarrow \\
&tf'(x)p^s = -f(x) + kp^{s+1} \\
&\Leftrightarrow \\
t =& \frac{-uf(x)}{p^s} + ukp \\
&\Leftrightarrow \\
t \equiv& \frac{-uf(x)}{p^s} \pmod p
\end{align}
$$

#### 2.2.2 P-adic Numbers

p-adic 数可以表示为

$$
c_{-n}p^{-n} + \cdots + c_0  + c_1p + \cdots + c_mp^m + ...
$$

p-adic数构成的域记为 $Q_p$ , 如果这些数没有负次幂(即， $c_i = 0, i<0$) 则表示为 $\mathbb Z_p$

我们 可以在p-adic 数构成的域上定义 椭圆曲线，使用 上文介绍的 lift 方法 ，lift $Q_p$ 上的椭圆曲线的点。这将允许我们将 ECDLP 约化(reduce)至 群 $p\mathbb Z_p$ 上。

#### 2.2.3 Curve Reduction Modulo P

令 $E(Q_p)$ 是定义在 p-adic 域上的椭圆曲线，通过约化 $E(Q_p): y^2 + x^3 + ax +b \mod p$ 的系数，得到 $E(F_p): y^2 = x^3 + \widetilde{a}x + \widetilde{b}$ 

点的映射也类似，对 $P = (x, y) \in E(Q_p), \widetilde{P} = (\widetilde{x}, \widetilde{y}) \in E(F_p), \widetilde{x} = x \pmod p, \widetilde{y} = y \pmod p$

这个映射是从 $E_(Q_p)$ 到 $E(F_p)$ 的群同态。

#### 2.2.4 P-adic Elliptic Logarithm

P-adic Elliptic Logarithm $\psi_p$ 提供了 $E_1(Q_p)$ 到 $p\mathbb Z_p$ 的同构。

对点 $S\in E_1(Q_p), \psi_p(S) = -\frac{x(S)}{y(S)}$ 

#### 2.2.5 The  Attack

lift $E(F_p)$ 上的点 P, Q 到 $E(Q_p)$ ，得到P', Q'。

因为在 $E(F_p)$ 上 $Q=kP$ ，所以 $Q' - kP'$  在 E(Q_p) 上 模p 为无穷远点。

$$
Q' - kP' \in E_1(Q_p)
$$

因为 $E(F_p)$ 的阶为p， 所以任意点 $R\in E(Q_p), pR \mod P$ 都将被约化为 $E(F_p)$ 上的 $\mathcal {O}$ ，所以  $E(Q_p)$ 的任意元素乘p，都将映射到 $E_1(Q_p)$

$$
pQ' - k(pP') \in E_2(Q_p)
$$

因为 $pQ' \in E_1(Q_p), pP' \in E_1(Q_p)$ , 可以应用 P-Adic Elliptic Log:

$$
\begin{align}
& \psi_p(pQ') - k\psi_p(pP') \in p\mathbb Z_p \\
\Rightarrow & \\
& k = \frac{\psi_p(pQ')}{\psi_p(pP')}
\end{align}
$$

再将 $k \mod p$ 以约化回 $F_p$ ，解决 ECDLP。

## 3. NIST Recommended Curve

nist 推荐的曲线，不满足Smart's Attack 的利用条件，Pohlig-Hellman attack 也不能起到加速效果。

## 4. 总结

介绍了两种对不当选择的椭圆曲线及其底层域的攻击方法。还有很多其他的攻击方法。