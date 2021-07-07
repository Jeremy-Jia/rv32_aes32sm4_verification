#include "saes32.h"
#include "sboxes.h"

// 函数代号码(op code)
#define SAES32_ENCSM	0				// 加密：字节替换 同时 列混合
#define SAES32_ENCS		1				// 加密：字节替换
#define SAES32_DECSM	2				// 解密：字节替换 同时 列混合
#define SAES32_DECS		3				// 解密：字节替换
#define SSM4_ED			4				// 
#define SSM4_KS			5				// 

static inline uint8_t aes_xtime(uint8_t x)
{
	/*
	* 伽罗瓦域乘法（LFSR算法）
	*	LFSR算法指，对一个8位的二进制数，求其伽罗瓦域的2倍值等于
	*			1) 如果最高位为0，则向左移动一位
	*			2) 如果最高位为1，则向左移动一位，然后与0b100011011进行亦或操作
	*			3）注：对于8位定长度而言，亦或的对象可以是0b11011
	* :param x			:			1
	* :return			:			1
	*/
	return (x << 1) ^ ((x & 0x80) ? 0x11B : 0x00);
}

// RV32通用执行码（AES/SM4加解密指令集通用）
uint32_t saes32(uint32_t rs1, uint32_t rs2, int fn)
{
	/*
	* 根据函数代号码执行相应运算
	* :param rs1		:		寄存器1内容
	* :param rs2		:		寄存器2内容
	* :param fn			:		操作指令编码及变量		例aes32encs: 代号码为2，变量为0/1/2/3， 则fa = 1_00 / 1_01 / 1_10 / 1_11
	* :return			:		对应操作的结果
	*/
	uint32_t fa;			// 从fn第1-0位提取的操作目标代码 fa = 1_00 / 1_01 / 1_10 / 1_11
	uint32_t fb;			// 从fn第5-2位提取的操作代码
	uint32_t x;				// 操作对象的输入输入字节（实际使用位数为8位）
	uint32_t x2;			// x值的2倍
	uint32_t x4;			// x值的4倍
	uint32_t x8;			// x值的8倍

	fa = 8 * (fn & 3);						//  [1:0]  提取第1-0位，对应操作目标	
	fb = (fn >> 2) & 7;						//  [4:2]  提取第5-2位，对应操作代码	&0d7 = &0b1111

	// 依据fn的代码编号（0/1/2/3）提取需要进行操作的对应字节
	// 即对32位寄存器内容的4个字节分别操作
	// 操作对象由fn的最右边两位决定（fa = 1_00 / 1_01 / 1_10 / 1_11）
	x = (rs2 >> fa) & 0xFF;					// 提取对应的字节（8 bits）

	// 执行S-box字节替换：输入8 bits，输出8 bits
	// 通过fb/操作代码寻找对应s_box
	switch (fb) {
	case SAES32_ENCSM:						//  fb == 0 : 执行AES加密字节替换与列混合	使用AES正盒
	case SAES32_ENCS:						//  fb == 1 : 执行AES加密自己替换			使用AES正盒
		x = aes_sbox[x];
		break;

	case SAES32_DECSM:						//  fb == 2 : 执行AES解密字节替换与列混合	使用AES逆盒
	case SAES32_DECS:						//  fb == 3 : 执行AES解密自己替换			使用AES逆盒
		x = aes_isbox[x];
		break;

	case SSM4_ED:							//  fb == 4 : 执行SM4加解密字节替换	使用SM4-Sbox
	case SSM4_KS:							//  fb == 5 : 执行SM4加解密字节替换	使用SM4-Sbox
		x = sm4_sbox[x];
		break;

	default:								//  其他操作代码则退出枚举
		break;
	}

	// 对AES加解密执行列混合操作
	//		1) 通过fb/操作代码确定对应操作
	//		2) 只有aes32esmi及aes32dsmi 亦即 当操作码为0或者2的时候才需要执行以下操作
	// 对SM4加解密执行线性变换操作
	//		1) 通过fb/操作代码确定对应操作
	//		2) 只有sm4ed及sm4ks 亦即 当操作码为4或者5的时候才需要执行以下操作
	switch (fb) {

	case SAES32_ENCSM:						//  操作代码为0 : AES加密过程列混合
		x2 = aes_xtime(x);					//  x 值乘以2，GF(2^8)伽罗瓦域乘法
		x = ((x ^ x2) << 24) |				//  0x03    正向列混合
			(x << 16) |						//  0x01
			(x << 8) |						//  0x01
			x2;								//  0x02
		break;

	case SAES32_DECSM:						//  操作代码为2 : AES解密过程列混合
		x2 = aes_xtime(x);					//  x 值乘以2，GF(2^8)伽罗瓦域乘法
		x4 = aes_xtime(x2);					//  x2 值乘以2，GF(2^8)伽罗瓦域乘法
		x8 = aes_xtime(x4);					//  x4 值乘以2，GF(2^8)伽罗瓦域乘法
		x = ((x ^ x2 ^ x8) << 24) |			//  0x0B    逆向列混合
			((x ^ x4 ^ x8) << 16) |			//  0x0D
			((x ^ x8) << 8) |				//  0x09
			(x2 ^ x4 ^ x8);					//  0x0E
		break;

	case SSM4_ED:							//  操作代码为4 : SM4线性L变换（加解密轮过程）
		x = x ^ (x << 8) ^ (x << 2) ^ (x << 18) ^
			((x & 0x3F) << 26) ^ ((x & 0xC0) << 10);
		break;

	case SSM4_KS:							//  操作代码为5 : SM4线性L'变换（密钥扩展过程过程）
		x = x ^ ((x & 0x07) << 29) ^ ((x & 0xFE) << 7) ^
			((x & 1) << 23) ^ ((x & 0xF8) << 13);
		break;

	default:								//  其他操作代码则退出枚举
		break;

	}

	// 如果fa不等于0，则需要左循环移动fa位
	if (fa != 0) {
		x = (x << fa) | (x >> (32 - fa));
	}

	return x ^ rs1;							//  与寄存器2的地址进行异或操作
}

// AES加密指令
uint32_t saes32_encsm(uint32_t rs1, uint32_t rs2, int bs)
{
	/*
	* 同aes32esmi函数 字节替换加列混合（需要调用S-box）
	* :param rs1		:		寄存器1地址
	* :param rs2		:		寄存器2地址
	* :param bs			:		指令代码（与RISCV指令代码有区别）
	* :return (rd)		:		返回运算结果，未指定变量名
	*/
	return saes32(rs1, rs2, (SAES32_ENCSM << 2) | bs);
}

uint32_t saes32_encs(uint32_t rs1, uint32_t rs2, int bs)
{
	/*
	* 同aes32esi函数 字节替换（需要调用S-box）
	* NOTE: 主要用于轮秘钥运算
	* :param rs1		:		寄存器1地址
	* :param rs2		:		寄存器2地址
	* :param bs			:		指令代码（与RISCV指令代码有区别）
	* :return (rd)		:		返回运算结果，未指定变量名
	*/

	// 按照目标字节（bs）进行运算
	return saes32(rs1, rs2, (SAES32_ENCS << 2) | bs);
}

// AES解密指令
uint32_t saes32_decsm(uint32_t rs1, uint32_t rs2, int bs)
{
	/*
	* 同aes32dsmi函数 字节替换加列混合（需要调用S-box）
	* :param rs1		:		寄存器1地址
	* :param rs2		:		寄存器2地址
	* :param bs			:		指令代码（与RISCV指令代码有区别）
	* :return (rd)		:		返回运算结果，未指定变量名
	*/
	return saes32(rs1, rs2, (SAES32_DECSM << 2) | bs);
}

uint32_t saes32_decs(uint32_t rs1, uint32_t rs2, int bs)
{
	/*
	* 同aes32dsmi函数 字节替换加列混合（需要调用S-box）
	* :param rs1		:		寄存器1地址
	* :param rs2		:		寄存器2地址
	* :param bs			:		指令代码（与RISCV指令代码有区别）
	* :return (rd)		:		返回运算结果，未指定变量名
	*/
	return saes32(rs1, rs2, (SAES32_DECS << 2) | bs);
}

// SM4相关指令
// SM4加解密指令集
uint32_t ssm4_ed(uint32_t rs1, uint32_t rs2, int bs)
{
	/*
	* 同sm3ed函数
	* :param rs1		:		寄存器1地址
	* :param rs2		:		寄存器2地址
	* :param bs			:		指令代码（与RISCV指令代码有区别）
	* :return (rd)		:		返回运算结果，未指定变量名
	*/
	return saes32(rs1, rs2, (SSM4_ED << 2) | bs);
}

// SM4秘钥扩展指令集
uint32_t ssm4_ks(uint32_t rs1, uint32_t rs2, int bs)
{
	/*
	* 同sm3ks函数
	* :param rs1		:		寄存器1地址
	* :param rs2		:		寄存器2地址
	* :param bs			:		指令代码（与RISCV指令代码有区别）
	* :return (rd)		:		返回运算结果，未指定变量名
	*/
	return saes32(rs1, rs2, (SSM4_KS << 2) | bs);
}
