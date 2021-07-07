#include "sm4_wrap.h"
#include "saes32.h"
#include "rv_endian.h"

// 按字节进行替换（加解密轮过程）
#define SSM4_ED_X4(rs1, rs2) {		\
	rs1 = ssm4_ed(rs1, rs2, 0);		\
	rs1 = ssm4_ed(rs1, rs2, 1);		\
	rs1 = ssm4_ed(rs1, rs2, 2);		\
	rs1 = ssm4_ed(rs1, rs2, 3);		\
}

// 按字节进行替换（密钥产生过程）
#define SSM4_KS_X4(rs1, rs2) {		\
	rs1 = ssm4_ks(rs1, rs2, 0);		\
	rs1 = ssm4_ks(rs1, rs2, 1);		\
	rs1 = ssm4_ks(rs1, rs2, 2);		\
	rs1 = ssm4_ks(rs1, rs2, 3);		\
}

//  encrypt or decrypt a block, depending on round key ordering

void sm4_encdec(uint8_t out[16], const uint8_t in[16], const uint32_t rk[SM4_RK_WORDS]){
	/*
	* 注：以下解释针对加密而言，对解密过程直接调转即可
	* 在SM4加密系统中将128位明文（in），结合对应轮次轮密钥（rk），加密成密文输出（out）
	* :param out	:		加密后密文输出，128位
	* :param in		:		加密前明文输入，128位
	* :param rk		:		加密使用的轮密钥
	*/
	uint32_t x0, x1, x2, x3;					// 加密轮的中间值
	uint32_t t, u;								// 中间变量
	const uint32_t* kp = &rk[SM4_RK_WORDS];		// 加解密轮终止符

	x0 = get32u_le(in);						// 输入转换为小端
	x1 = get32u_le(in + 4);
	x2 = get32u_le(in + 8);
	x3 = get32u_le(in + 12);

	do {

		u = x2 ^ x3;						// X2 ^ X3
		t = rk[0];							// 导入当前轮的轮密钥	
		t ^= u;								// X2 ^ X3 ^ rk_i
		t ^= x1;							// X1 ^ X2 ^ X3 ^ rk_i
		SSM4_ED_X4(x0, t);					// S-box 字节替换


		t = rk[1];							// 导入当前轮的轮密钥
											// u = X1 ^ X2
		t ^= u;								// X1 ^ X2 ^ rk_i
		t ^= x0;							// X1 ^ X2 ^ X3 ^ rk_i
		SSM4_ED_X4(x1, t);					// S-box 字节替换
		
		u = x0 ^ x1;						// X2 ^ X3
		t = rk[2];							// 导入当前轮的轮密钥
		t ^= u;								// X2 ^ X3 ^ rk_i
		t ^= x3;							// X1 ^ X2 ^ X3 ^ rk_i
		SSM4_ED_X4(x2, t);					// S-box 字节替换

		t = rk[3];							// 导入当前轮的轮密钥
											// u = X1 ^ X2
		t ^= u;								// X1 ^ X2 ^ rk_i
		t ^= x2;							// X1 ^ X2 ^ X3 ^ rk_i
		SSM4_ED_X4(x3, t);					// S-box 字节替换

		rk += 4;							// 轮密钥指针前移

	} while (rk != kp);

	// 最后的加解密结果存储于out（四个字需要前后调换顺序）
	put32u_le(out, x3);
	put32u_le(out + 4, x2);
	put32u_le(out + 8, x1);
	put32u_le(out + 12, x0);
}



void sm4_enc_key(uint32_t rk[SM4_RK_WORDS], const uint8_t key[16])
{
	/*
	* 在SM4加密系统中将128位加密秘钥扩展为32个扩展秘钥字
	* :param key	:		key，执行扩展之前的秘钥，128位
	* :param rk		:		round key，扩展以后的轮秘钥。
	*/
	const uint32_t* kp = &rk[SM4_RK_WORDS];
	uint32_t x0, x1, x2, x3;				// 密钥产生的中间字
	uint32_t t, u, ck;

	// 密钥初始化
	x0 = get32u_le(key);					// MK_0
	x1 = get32u_le(key + 4);				// MK_1
	x2 = get32u_le(key + 8);				// MK_2
	x3 = get32u_le(key + 12);				// MK_3

	// 初始化K_0 - K_3
	x0 ^= 0xC6BAB1A3;						// K_0 = MK_0 ^ FK_0
	x1 ^= 0x5033AA56;						// K_1 = MK_1 ^ FK_1						
	x2 ^= 0x97917D67;						// K_2 = MK_2 ^ FK_2
	x3 ^= 0xDC2270B2;						// K_3 = MK_3 ^ FK_3

	ck = 0x140E0600;						// 固定取值CK_0，后续CK由算法算出（小端存储）

	do {
		/*
		* CK的产生方法：
		*	SM4中的"CK"为密钥生成过程中使用的一种常数，产生规则是：
		*		1) 设变量 CK_i
		*		2) j 为 CK_i 的第 j 字节(i = 0, 1, ..., 31; j = 0, 1, 2, 3)
		*		3) CK_j = (CK_i0, CK_i1, CK_i2, CK_i3)
		*		4) CK_ij = (4 * i + j ) * 7 (mod 256)
		*/
		t = ck ^ 0x01000100;				// t 为正确的，产生轮密钥使用的ck
		ck += 0x1C1C1C1C;					// 下一个ck的产生过程
		ck &= 0xFEFEFEFE;					

		// K_i+1 ^ K_i+2 ^ K_i+3 ^ CK_i
		u = x2 ^ x3;						
		t = t ^ u;
		t = t ^ x1;
		SSM4_KS_X4(x0, t);					//  执行SM4_KS函数

		rk[0] = x0;							// 初始化密钥扩展空间，并赋值给第一个rk0

		t = ck ^ 0x01000100;
		ck += 0x1C1C1C1C;
		ck &= 0xFEFEFEFE;

		t = t ^ u;
		t = t ^ x0;
		SSM4_KS_X4(x1, t);					
		rk[1] = x1;

		t = ck ^ 0x01000100;
		ck += 0x1C1C1C1C;
		ck &= 0xFEFEFEFE;

		u = x0 ^ x1;
		t ^= u;
		t ^= x3;
		SSM4_KS_X4(x2, t);					
		rk[2] = x2;

		t = ck ^ 0x01000100;
		ck += 0x1C1C1C1C;
		ck &= 0xFEFEFEFE;

		t ^= u;
		t ^= x2;
		SSM4_KS_X4(x3, t);					
		rk[3] = x3;

		rk += 4;

	} while (rk != kp);
}


void sm4_dec_key(uint32_t rk[SM4_RK_WORDS], const uint8_t key[16])
{
	/*
	* 在SM4加密系统中将128位加密秘钥扩展为32个扩展秘钥字
	* :param key	:		key，执行扩展之前的秘钥，128位
	* :param rk		:		round key，扩展以后的轮秘钥。
	*/
	uint32_t t;
	int i, j;

	sm4_enc_key(rk, key);					//  解密密钥使用加密密钥扩展过程

	// 解密过程使用加密密钥进行倒序排列
	for (i = 0, j = SM4_RK_WORDS - 1; i < j; i++, j--) {
		t = rk[i];
		rk[i] = rk[j];
		rk[j] = t;
	}
}
