---

tags: crypto

---

# 勘误：Boneh-1996： MSB 定义错误

最近在学习格相关知识的时候，读到 Boneh 和 Venkatesan 1996年的论文
'Hardness of computing the most significant bits of secret keys in Diffie-Hellman and related schemes'，这篇论文第一次提出了 HNP(Hidden Number Problem) 。

其中提出的 $MSB_k(x)$ 函数的定义似乎有一些小问题。

我找到了两个版本的论文, 内容基本一致：

https://crypto.stanford.edu/~dabo/pubs/abstracts/dhmsb.html

Let $p$ be a prime number and $n=\lceil \log p\rceil$ be its length in binary. We use $x\mod p$ to denote the unique interger a in the range $[0, p-1]$ satisfying $x \equiv a \pmod p$ . Given a prime $p$ , we define $MSB_k(x)$ as the integer $t$ such that $(t-1)\cdot p/2^k \le x \lt t\cdot p/2^k$ . For example, $MSB_1(x)$ is either 0 or 1 depending on whether x is smaller than or greater than $p/2$ .

https://citeseerx.ist.psu.edu/document?repid=rep1&type=pdf&doi=c8f9439df73b065e124000e23a504d1dbe4ae79d

We will often refer to the function $MSB_k(x)$ where $0\le x\lt p$ . Given a prime $p$ the function $MSB_k(x)$ is defined to be the integer $t$ such that $(t-1)\cdot p/2^k \le x \lt t\cdot p/2^k$ . For example, $MSB_1(x)$ is either 0 or 1 depending on whether x is smaller than or greater than $p/2$ .

其中的错误是很显然的， $MSB_1(x)$ 不可能为0， 否则 $x < 0$ ，与 x 的范围定义矛盾。

这是一个很小的错误，更可能是笔误，不影响全文任何结论。不过还是对我的学习造成了些许困扰。有可能 Boneh 后来发现了这个笔误，但经我简单搜索，未见公开资料说明这一问题。故在此记录，以供后来有相同困惑的同学参考。

另外，我发现 Steven Galbraith 教授的 crypto-book 'Mathematics of Public Key Cryptography' 中也支撑了我的观点, 他修正了 MSB 的定义：

https://www.math.auckland.ac.nz/~sgal018/crypto-book/ch21.pdf

**Definition 21.7.1.** Let $p$ be odd. Let $x\in{1,2,\cdots,p-1}$ . Define

$$
MSB_1(x) = \left\lbrace\begin{array}{rcl}& 0 & if 1 \le  x \lt p/2 \\& 1 & otherwise. \end{array} \right.
$$

For $k\in \mathbb N$ let $0\le t \lt 2^k$ be the integer such that 

$$
tp/2^k \le x \lt (t+1)p/2^k
$$

and define $MSB_k(x)=t$ .


与 Boneh 原论文相比，这个定义要更明确、容易理解。


----

本文同步发表于

* blog: ssst0n3.github.io
* 公众号: 石头的安全料理屋
* 知乎专栏: 石头的安全料理屋
