# YHAES

AES
高级加密标准(Advanced Encryption Standard)
在密码学中又称Rijndael加密法,是美国联邦政府采用的一种区块加密标准;
这个标准用来替代原先的DES,已经被多方分析且广为全世界所使用,经过五年的甄选流程;
高级加密标准由美国国家标准与技术研究院（NIST）于2001年11月26日发布于FIPS PUB 197;
并在2002年5月26日成为有效的标准;
2006年,高级加密标准已然成为对称密钥加密中最流行的算法之一.

一.设计者
该算法为比利时密码学家 Joan Daemen 和 Vincent Rijmen 所设计;
结合两位作者的名字,以 Rijndael 之命名之,投稿高级加密标准的甄选流程。
Rijdael 的发音近于"Rhinedoll",两位设计者的名字,参考荷兰语原发音可译为尤安·达蒙、文森特·莱蒙;
Joan 不能译为女性化的名字"琼".另外,西欧的姓名很多是有相同拉丁文或希腊文源头的,故译成中文是可能相同.

二.设计思想
Rijndael密码的设计力求满足以下3条标准:
1)抵抗所有已知的攻击
2)在多个平台上速度快、编码紧凑
3)设计简单
当前的大多数分组密码,其轮函数是 Feistel 结构;
Rijndael 没有这种结构;
Rijndael 轮函数是由3个不同的可逆均匀变换.

三.密码说明
AES 和 Rijndael 加密法并不完全一样,虽然在实际应用中二者可以互换;
因为 Rijndael 加密法可以支持更大范围的区块和密钥长度:AES的区块长度固定为128 比特,密钥长度则可以是128,192或256比特;
而 Rijndael 使用的密钥和区块长度可以是32位的整数倍,以128位为下限,256比特为上限.加密过程中使用的密钥是由Rijndael密钥生成方案产生.
大多数AES计算是在一个特别的有限域完成的.
AES加密过程是在一个4×4的字节矩阵上运作,这个矩阵又称为"状态 state",其初值就是一个明文区块,矩阵中一个元素大小就是明文区块中的一个Byte.
Rijndael 加密法因支持更大的区块,其矩阵行数可视情况增加.加密时,各轮AES加密循环,除最后一轮外,均包含4个步骤：
1)AddRoundKey — 矩阵中的每一个字节都与该次轮秘钥(round key)做XOR运算,每个子密钥由密钥生成方案产生;
2)SubBytes — 通过非线性的替换函数,用查找表的方式把每个字节替换成对应的字节;
3)ShiftRows — 将矩阵中的每个横列进行循环式移位;
4)MixColumns — 为了充分混合矩阵中各个直行的操作.该步骤使用线性转换来混合每列的四个字节.
最后一个加密循环中省略 MixColumns 的步骤,而以另外一个 AddRoundKey 来取代.

四.加密标准
对称密码体制的发展趋势将以分组密码为重点.
分组密码算法通常由密钥扩展算法和加密、解密算法两部分组成;
密钥扩展算法将 b 字节用户主密钥扩展成 r 个子密钥;
加密算法由一个密码学上的弱函数 f 与 r 个子密钥迭代 r 次组成;
混乱和密钥扩散是分组密码算法设计的基本原则.抵御已知明文的差分和线性攻击,可变长密钥和分组是该体制的设计要点.

AES是美国国家标准技术研究所NIST旨在取代DES的21世纪的加密标准.
其 AES 的基本要求是采用对称分组密码体制,密钥的长度最少支持为128、192、256,分组长度128位,算法应易于各种硬件和软件实现.
1998年NIST开始AES第一轮分析、测试和征集,共产生了15个候选算法.
1999年3月完成了第二轮AES2的分析、测试.
2000年10月2日美国政府正式宣布选中比利时密码学家 Joan Daemen 和 Vincent Rijmen 提出的一种密码算法 RIJNDAEL 作为 AES.

在应用方面,尽管DES在安全上是脆弱的,但由于快速DES芯片的大量生产,使得DES仍能暂时继续使用;
为提高安全强度,通常使用独立密钥的三级DES,但是 DES 迟早要被 AES 代替;
流密码体制较之分组密码在理论上成熟且安全,但未被列入下一代加密标准!

AES加密数据块分组长度必须为128比特,密钥长度可以是128比特、192比特、256比特中的任意一个;
如果数据块及密钥长度不足时会补齐.AES加密有很多轮的重复和变换,大致步骤如下:
1)密钥扩展 KeyExpansion
2)初始轮 Initial Round 
3)重复轮 Rounds,其中每一轮又包括:SubBytes、ShiftRows、MixColumns、AddRoundKey
4)最终轮 Final Round(注:最终轮没有 MixColumns)








