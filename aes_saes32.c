/* ******************** RV-32 加密函数测试文档 ********************
* 工程主体： 山东大学
* 主工程文件： 闻乙名
*
* 创建日期：03.32.2020 8:50
* 主设计名称：RV32 加密函数测试文档
* 模块名称：RV32 加密模块函数文件
*
* 依赖文件：
* aes_saes32.h			:		RV32 加密模块头文件（header）

* 说明：
*	1) 加解密过程为乒乓过程，具体解释在代码中有体现
*
**************************************************************** */

#include <stddef.h>

#include "saes32.h"
#include "aes_wrap.h"					// AES包装函数
#include "bitmanip.h"					// 比特级别操作函数
#include "rv_endian.h"					// 大小端转换函数
#include "sboxes.h"						// S-box数据


/*
* ******************** 加密过程 ********************
* 加密轮数，依照AES 128/192/256的加密过程不同，加密轮数不同
*		AES-128		：		10轮
*		AES-192		：		12轮
*		AES-256		：		14轮
*/

void aes_enc_rounds_saes32(uint8_t ct[16], const uint8_t pt[16], const uint32_t rk[], int nr)
{
	/*
	* 根据明文（pt/128字节）轮秘钥（rk/长度未定）进行加密，加密后的结果存入密文（ct/128字节）
	* :param ct[16]		:				密文，长度为128字节
	* :param pt[16]		:				明文，长度为128字节
	* :param rk[]		:				轮密钥，依据AES算法有不同，为AES-128/44，AES-192/52，AES-256/60个密钥字
	* :param nr			:				加密轮数
	* :return 			:				由t0、t1、t2、t3定义的返回指针 --> 指向ct
	*/
	uint32_t t0, t1, t2, t3;				//  偶数加密轮寄存器初始化 
	uint32_t u0, u1, u2, u3;				//  奇数加密轮寄存器初始化 
	const uint32_t* kp = &rk[4 * nr];		//  初始化秘钥终止指针 

	// 秘钥初始化（K0）：
	t0 = rk[0];			// K0_W0
	t1 = rk[1];			// K0_W1
	t2 = rk[2];			// K0_W2
	t3 = rk[3];			// K0_W3

	// 轮密相加（第一轮开始以前要将初始密钥和明文进行亦或）
	t0 ^= get32u_le(pt);					
	t1 ^= get32u_le(pt + 4);				
	t2 ^= get32u_le(pt + 8);
	t3 ^= get32u_le(pt + 12);

	while (1) {	
		/*
		* 注：
		*	1) 该过程为一个乒乓过程，即初始化奇数轮加密与偶数轮加密数据空间。
		*	2) 通过反复覆盖结果实现对数据的加密，同时减少寄存器空间的使用
		*	3) 行移位过程由调用数据的字节编号实现
		*/

		// 奇数轮加密
		u0 = rk[4];							// 密钥初始化
		u1 = rk[5];
		u2 = rk[6];
		u3 = rk[7];

		// 第一个字
		u0 = saes32_encsm(u0, t0, 0);		// 字节替换与列混合
		u0 = saes32_encsm(u0, t1, 1);
		u0 = saes32_encsm(u0, t2, 2);
		u0 = saes32_encsm(u0, t3, 3);

		// 第二个字
		u1 = saes32_encsm(u1, t1, 0);
		u1 = saes32_encsm(u1, t2, 1);
		u1 = saes32_encsm(u1, t3, 2);
		u1 = saes32_encsm(u1, t0, 3);

		// 第三个字
		u2 = saes32_encsm(u2, t2, 0);
		u2 = saes32_encsm(u2, t3, 1);
		u2 = saes32_encsm(u2, t0, 2);
		u2 = saes32_encsm(u2, t1, 3);

		// 第四个字
		u3 = saes32_encsm(u3, t3, 0);
		u3 = saes32_encsm(u3, t0, 1);
		u3 = saes32_encsm(u3, t1, 2);
		u3 = saes32_encsm(u3, t2, 3);

		// 偶数轮加密
		t0 = rk[8];							//  密钥初始化
		t1 = rk[9];
		t2 = rk[10];
		t3 = rk[11];

		rk += 8;							//  如果达到跳出指针，则跳出当前加密循环
		if (rk == kp)						
			break;

		// 第一个字
		t0 = saes32_encsm(t0, u0, 0);		
		t0 = saes32_encsm(t0, u1, 1);
		t0 = saes32_encsm(t0, u2, 2);
		t0 = saes32_encsm(t0, u3, 3);

		// 第二个字
		t1 = saes32_encsm(t1, u1, 0);
		t1 = saes32_encsm(t1, u2, 1);
		t1 = saes32_encsm(t1, u3, 2);
		t1 = saes32_encsm(t1, u0, 3);

		// 第三个字
		t2 = saes32_encsm(t2, u2, 0);
		t2 = saes32_encsm(t2, u3, 1);
		t2 = saes32_encsm(t2, u0, 2);
		t2 = saes32_encsm(t2, u1, 3);

		// 第四个字
		t3 = saes32_encsm(t3, u3, 0);
		t3 = saes32_encsm(t3, u0, 1);
		t3 = saes32_encsm(t3, u1, 2);
		t3 = saes32_encsm(t3, u2, 3);
	}

	// 最后一轮加密，不进行列混合，则使用esi函数
	t0 = saes32_encs(t0, u0, 0);			
	t0 = saes32_encs(t0, u1, 1);
	t0 = saes32_encs(t0, u2, 2);
	t0 = saes32_encs(t0, u3, 3);

	t1 = saes32_encs(t1, u1, 0);
	t1 = saes32_encs(t1, u2, 1);
	t1 = saes32_encs(t1, u3, 2);
	t1 = saes32_encs(t1, u0, 3);

	t2 = saes32_encs(t2, u2, 0);
	t2 = saes32_encs(t2, u3, 1);
	t2 = saes32_encs(t2, u0, 2);
	t2 = saes32_encs(t2, u1, 3);

	t3 = saes32_encs(t3, u3, 0);
	t3 = saes32_encs(t3, u0, 1);
	t3 = saes32_encs(t3, u1, 2);
	t3 = saes32_encs(t3, u2, 3);

	// 按照大端输出加密后信息
	// 将t0-t3的加密结果存储到ct
	put32u_le(ct, t0);				//	0 -  31 位
	put32u_le(ct + 4, t1);			// 32 -  63 位
	put32u_le(ct + 8, t2);			// 64 -  95 位
	put32u_le(ct + 12, t3);			// 96 - 128 位
}

// AES-128 加密过程包装器
void aes128_enc_ecb_saes32(uint8_t ct[16], const uint8_t pt[16], const uint32_t rk[AES128_RK_WORDS])
{
	/*
	* 对明文（pt/128字节）使用秘钥（rk/44个扩展字）加密，输出密文（ct/128字节）
	* :param pt		:		明文，128字节
	* :param ct		:		密文，128字节
	* :param rk		:		扩展后的秘钥，44个扩展字（4 bytes/words）
	* :return (ct)	:		加密之后的结果，输出到ct/128字节
	*/
	aes_enc_rounds_saes32(ct, pt, rk, AES128_ROUNDS);
}

// AES-192 加密过程包装器
void aes192_enc_ecb_saes32(uint8_t ct[16], const uint8_t pt[16], const uint32_t rk[AES192_RK_WORDS])
{
	/*
	* 对明文（pt/128字节）使用秘钥（rk/52个扩展字）加密，输出密文（ct/128字节）
	* :param pt		:		明文，128字节
	* :param ct		:		密文，128字节
	* :param rk		:		扩展后的秘钥，52个扩展字（4 bytes/words）
	* :return (ct)	:		加密之后的结果，输出到ct/128字节
	*/
	aes_enc_rounds_saes32(ct, pt, rk, AES192_ROUNDS);
}

// AES-256 加密过程包装器
void aes256_enc_ecb_saes32(uint8_t ct[16], const uint8_t pt[16], const uint32_t rk[AES256_RK_WORDS])
{
	/*
	* 对明文（pt/128字节）使用秘钥（rk/60个扩展字）加密，输出密文（ct/128字节）
	* :param pt		:		明文，128字节
	* :param ct		:		密文，128字节
	* :param rk		:		扩展后的秘钥，60个扩展字（4 bytes/words）
	* :return (ct)	:		加密之后的结果，输出到ct/128字节
	*/
	aes_enc_rounds_saes32(ct, pt, rk, AES256_ROUNDS);
}

// AES-128 的秘钥扩展函数（加密过程）
void aes128_enc_key_saes32(uint32_t rk[44], const uint8_t key[16])
{
	/*
	* 在AES-128加密系统中将128位加密秘钥扩展为44个扩展秘钥字
	* :param key	:		key，执行扩展之前的秘钥，128位
	* :param rk		:		round key，扩展以后的轮秘钥，44个字，每个字4个字节
	*/
	uint32_t t0, t1, t2, t3, tr;			// 轮秘钥寄存器空间
	const uint32_t* rke = &rk[44 - 4];		// 结束标志指针，运行到此位置时程序跳出
	const uint8_t* rc = aes_rcon;			// 轮常数（sboxes.c）

	// 初始秘钥存入寄存器
	t0 = get32u_le(key);					// 第一个字，小端0x03020100
	t1 = get32u_le(key + 4);				// 第二个字，小端0x07060504
	t2 = get32u_le(key + 8);				// 第三个字，小端0x0b0a0908
	t3 = get32u_le(key + 12);				// 第四个字，小端0x0f0e0d0c

	// 对AES-128加密，本过程重复10轮
	while (1) {
		rk[0] = t0;							// 指针起点字
		rk[1] = t1;							// 指针起点+1字
		rk[2] = t2;							// 指针起点+2字
		rk[3] = t3;							// 指针起点+3字

		// 判断指针是否到终点，如果执行到结束指针，则程序跳出，否则指针起点前移4个字
		if (rk == rke)						// 终点判断
			return;
		rk += 4;							// 未到终点，指针前移4个字

		t0 ^= (uint32_t)*rc++;			// 轮常数读取，读取以后，轮常数自加1，其值与W0亦或
		tr = rv32b_ror(t3, 8);			// W3向左循环移位（小端模式向右1字节）		T函数第一步
		t0 = saes32_encs(t0, tr, 0);	// 字节替换过程，替换w[][0]					T函数第二步
		t0 = saes32_encs(t0, tr, 1);	// 字节替换过程，替换w[][1]
		t0 = saes32_encs(t0, tr, 2);	// 字节替换过程，替换w[][2]
		t0 = saes32_encs(t0, tr, 3);	// 字节替换过程，替换w[][3]					T函数第三步
		t1 ^= t0;						// 更新W5			
		t2 ^= t1;						// 更新W6			
		t3 ^= t2;						// 更新W7			
	}
}

// AES-192 的秘钥扩展函数（加密过程）
void aes192_enc_key_saes32(uint32_t rk[52], const uint8_t key[24])
{
	/*
	* 在AES-192加密系统中将192位加密秘钥扩展为52个扩展秘钥字
	* :param key	:		key，执行扩展之前的秘钥，128位
	* :param rk		:		round key，扩展以后的轮秘钥，52个字，每个字4个字节
	*/
	uint32_t t0, t1, t2, t3, t4, t5, tr;	// 轮秘钥寄存器空间
	const uint32_t* rke = &rk[52 - 4];		// 结束标志指针，运行到此位置时程序跳出
	const uint8_t* rc = aes_rcon;			// 轮常数（sboxes.c）

	t0 = get32u_le(key);					// 第一个字，小端0x03020100
	t1 = get32u_le(key + 4);				// 第二个字，小端0x07060504
	t2 = get32u_le(key + 8);				// 第三个字，小端0x0b0a0908
	t3 = get32u_le(key + 12);				// 第四个字，小端0x0f0e0d0c
	t4 = get32u_le(key + 16);				// 第五个字，小端0x12121110
	t5 = get32u_le(key + 20);				// 第六个字，小端0x17161514

	// 对AES-192加密，本过程重复12轮
	while (1) {
		rk[0] = t0;							// 指针起点字
		rk[1] = t1;							// 指针起点+1字
		rk[2] = t2;							// 指针起点+2字
		rk[3] = t3;							// 指针起点+3字

		// 判断指针是否到终点，如果执行到结束指针，则程序跳出，否则指针起点前移6个字
		if (rk == rke)						// 终点判断
			return;

		rk[4] = t4;							// 指针起点+4字
		rk[5] = t5;							// 指针起点+5字
		rk += 6;							// 未到终点，指针前移6个字

		t0 ^= (uint32_t)*rc++;					// 轮常数读取，读取以后，轮常数自加1，其值与W0亦或
		tr = rv32b_ror(t5, 8);					// W5向左循环移位（小端模式向右1字节）		T函数第一步
		t0 = saes32_encs(t0, tr, 0);			// 字节替换过程，替换w[][0]					T函数第二步
		t0 = saes32_encs(t0, tr, 1);			// 字节替换过程，替换w[][1]
		t0 = saes32_encs(t0, tr, 2);			// 字节替换过程，替换w[][2]
		t0 = saes32_encs(t0, tr, 3);			// 字节替换过程，替换w[][3]					T函数第三步

		t1 ^= t0;			// 更新W7
		t2 ^= t1;			// 更新W8
		t3 ^= t2;			// 更新W9
		t4 ^= t3;			// 更新W10
		t5 ^= t4;			// 更新W11
	}
}

// AES-256 的秘钥扩展函数（加密过程）
void aes256_enc_key_saes32(uint32_t rk[60], const uint8_t key[32])
{
	/*
	* 在AES-192加密系统中将192位加密秘钥扩展为60个扩展秘钥字
	* :param key	:		key，执行扩展之前的秘钥，128位
	* :param rk		:		round key，扩展以后的轮秘钥，60个字，每个字4个字节
	*/
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, tr;		// 轮秘钥寄存器空间
	const uint32_t* rke = &rk[60 - 4];					// 结束标志指针，运行到此位置时程序跳出
	const uint8_t* rc = aes_rcon;						// 轮常数（sboxes.c）

	t0 = get32u_le(key);				// 第一个字，小端0x03020100
	t1 = get32u_le(key + 4);			// 第二个字，小端0x07060504
	t2 = get32u_le(key + 8);			// 第三个字，小端0x0b0a0908
	t3 = get32u_le(key + 12);			// 第四个字，小端0x0f0e0d0c
	t4 = get32u_le(key + 16);			// 第五个字，小端0x12121110
	t5 = get32u_le(key + 20);			// 第六个字，小端0x17161514
	t6 = get32u_le(key + 24);			// 第七个字，小端0x1b1a1918
	t7 = get32u_le(key + 28);			// 第八个字，小端0x1f1e1d1c

	rk[0] = t0;								// 指针起点字
	rk[1] = t1;								// 指针起点+1字
	rk[2] = t2;								// 指针起点+2字
	rk[3] = t3;								// 指针起点+3字

	// 对AES-192加密，本过程重复14轮
	while (1) {

		rk[4] = t4;							// 指针起点字
		rk[5] = t5;							// 指针起点字
		rk[6] = t6;							// 指针起点字
		rk[7] = t7;							// 指针起点字
		rk += 8;							// 未到终点，指针前移8个字

		t0 ^= (uint32_t)*rc++;				// 轮常数读取，读取以后，轮常数自加1，其值与W0亦或
		tr = rv32b_ror(t7, 8);				// W7向左循环移位（小端模式向右1字节）		T函数第一步
		t0 = saes32_encs(t0, tr, 0);		// 字节替换过程，替换w[][0]					T函数第二步
		t0 = saes32_encs(t0, tr, 1);		// 字节替换过程，替换w[][1]
		t0 = saes32_encs(t0, tr, 2);		// 字节替换过程，替换w[][2]
		t0 = saes32_encs(t0, tr, 3);		// 字节替换过程，替换w[][3]
		t1 ^= t0;			// 更新W9
		t2 ^= t1;			// 更新W10
		t3 ^= t2;			// 更新W11

		rk[0] = t0;							// 存入W8
		rk[1] = t1;							// 存入W9
		rk[2] = t2;							// 存入W10
		rk[3] = t3;							// 存入W11

		// 判断指针是否到终点，如果执行到结束指针，则程序跳出，否则指针起点前移8个字
		if (rk == rke)						// 终点判断
			return;

		t4 = saes32_encs(t4, t3, 0);		//  SubWord() - NO rotation
		t4 = saes32_encs(t4, t3, 1);
		t4 = saes32_encs(t4, t3, 2);
		t4 = saes32_encs(t4, t3, 3);
		t5 ^= t4;			// 更新W13
		t6 ^= t5;			// 更新W14
		t7 ^= t6;			// 更新W15
	}
}


/*
* ******************** 解密过程 ********************
* 解密轮数，依照AES 128/192/256的加密过程不同，解密轮数不同
*		AES-128		：		10轮
*		AES-192		：		12轮
*		AES-256		：		14轮
*/

void aes_dec_rounds_saes32(uint8_t pt[16], const uint8_t ct[16], const uint32_t rk[], int nr)
{
	/*
	* 根据密文（ct/128字节）轮秘钥（rk/长度未定）进行解密，加密后的结果存入密文（pt/128字节）
	* :param pt[16]		:				明文，长度为128字节
	* :param ct[16]		:				密文，长度为128字节
	* :param rk[]		:				轮密钥，依据AES算法有不同，为AES-128/44，AES-192/52，AES-256/60个密钥字
	* :param nr			:				加密轮数
	* :return 			:				由t0、t1、t2、t3定义的返回指针 --> 指向pt
	*/
	uint32_t t0, t1, t2, t3;				//  偶数解密轮寄存器初始化 
	uint32_t u0, u1, u2, u3;				//  奇数解密轮寄存器初始化
	const uint32_t* kp = &rk[4 * nr];		//  初始化秘钥终止指针

	// 秘钥初始化（K0）：
	t0 = kp[0];			// K0_W0			
	t1 = kp[1];			// K0_W1
	t2 = kp[2];			// K0_W2
	t3 = kp[3];			// K0_W3
	kp -= 8;

	// 轮密相加（第一轮开始以前要将初始密钥和密文进行亦或）
	t0 ^= get32u_le(ct);					
	t1 ^= get32u_le(ct + 4);
	t2 ^= get32u_le(ct + 8);
	t3 ^= get32u_le(ct + 12);

	while (1) {
		/*
		* 注：
		*	1) 该过程为一个乒乓过程，即初始化奇数轮加密与偶数轮加密数据空间。
		*	2) 通过反复覆盖结果实现对数据的加密，同时减少寄存器空间的使用
		*	3) 行移位过程由调用数据的字节编号实现
		*/

		// 奇数轮解密
		u0 = kp[4];							
		u1 = kp[5];
		u2 = kp[6];
		u3 = kp[7];

		// 第一个字
		u0 = saes32_decsm(u0, t0, 0);		// 字节替换与列混合
		u0 = saes32_decsm(u0, t3, 1);
		u0 = saes32_decsm(u0, t2, 2);
		u0 = saes32_decsm(u0, t1, 3);

		// 第二个字
		u1 = saes32_decsm(u1, t1, 0);
		u1 = saes32_decsm(u1, t0, 1);
		u1 = saes32_decsm(u1, t3, 2);
		u1 = saes32_decsm(u1, t2, 3);

		// 第三个字
		u2 = saes32_decsm(u2, t2, 0);
		u2 = saes32_decsm(u2, t1, 1);
		u2 = saes32_decsm(u2, t0, 2);
		u2 = saes32_decsm(u2, t3, 3);

		// 第四个字
		u3 = saes32_decsm(u3, t3, 0);
		u3 = saes32_decsm(u3, t2, 1);
		u3 = saes32_decsm(u3, t1, 2);
		u3 = saes32_decsm(u3, t0, 3);

		// 偶数轮加密
		t0 = kp[0];							//  密钥初始化
		t1 = kp[1];
		t2 = kp[2];
		t3 = kp[3];

		if (kp == rk)						//  如果达到跳出指针，则跳出当前加密循环
			break;
		kp -= 8;

		// 第一个字
		t0 = saes32_decsm(t0, u0, 0);		
		t0 = saes32_decsm(t0, u3, 1);
		t0 = saes32_decsm(t0, u2, 2);
		t0 = saes32_decsm(t0, u1, 3);

		// 第二个字
		t1 = saes32_decsm(t1, u1, 0);
		t1 = saes32_decsm(t1, u0, 1);
		t1 = saes32_decsm(t1, u3, 2);
		t1 = saes32_decsm(t1, u2, 3);

		// 第三个字
		t2 = saes32_decsm(t2, u2, 0);
		t2 = saes32_decsm(t2, u1, 1);
		t2 = saes32_decsm(t2, u0, 2);
		t2 = saes32_decsm(t2, u3, 3);

		// 第四个字
		t3 = saes32_decsm(t3, u3, 0);
		t3 = saes32_decsm(t3, u2, 1);
		t3 = saes32_decsm(t3, u1, 2);
		t3 = saes32_decsm(t3, u0, 3);
	}

	// 最后一轮加密，不进行列混合，则使用dsi函数
	t0 = saes32_decs(t0, u0, 0);			
	t0 = saes32_decs(t0, u3, 1);
	t0 = saes32_decs(t0, u2, 2);
	t0 = saes32_decs(t0, u1, 3);

	t1 = saes32_decs(t1, u1, 0);
	t1 = saes32_decs(t1, u0, 1);
	t1 = saes32_decs(t1, u3, 2);
	t1 = saes32_decs(t1, u2, 3);

	t2 = saes32_decs(t2, u2, 0);
	t2 = saes32_decs(t2, u1, 1);
	t2 = saes32_decs(t2, u0, 2);
	t2 = saes32_decs(t2, u3, 3);

	t3 = saes32_decs(t3, u3, 0);
	t3 = saes32_decs(t3, u2, 1);
	t3 = saes32_decs(t3, u1, 2);
	t3 = saes32_decs(t3, u0, 3);

	// 按照大端输出加密后信息
	// 将t0-t3的加密结果存储到pt	
	put32u_le(pt, t0);						
	put32u_le(pt + 4, t1);
	put32u_le(pt + 8, t2);
	put32u_le(pt + 12, t3);
}

// AES-128 解密过程包装器
void aes128_dec_ecb_saes32(uint8_t pt[16], const uint8_t ct[16], const uint32_t rk[AES128_RK_WORDS])
{
	/*
	* 对密文（ct/128字节）使用秘钥（rk/44个扩展字）加密，输出解密后的明文（pt/128字节）
	* :param pt		:		明文，128字节
	* :param ct		:		密文，128字节
	* :param rk		:		扩展后的秘钥，44个扩展字（4 bytes/words）
	* :return (pt)	:		解密之后的结果，输出到pt/128字节
	*/
	aes_dec_rounds_saes32(pt, ct, rk, AES128_ROUNDS);
}

// AES-192 解密过程包装器
void aes192_dec_ecb_saes32(uint8_t pt[16], const uint8_t ct[16], const uint32_t rk[AES192_RK_WORDS])
{
	/*
	* 对密文（ct/128字节）使用秘钥（rk/52个扩展字）加密，输出解密后的明文（pt/128字节）
	* :param pt		:		明文，128字节
	* :param ct		:		密文，128字节
	* :param rk		:		扩展后的秘钥，52个扩展字（4 bytes/words）
	* :return (pt)	:		解密之后的结果，输出到pt/128字节
	*/
	aes_dec_rounds_saes32(pt, ct, rk, AES192_ROUNDS);
}

// AES-256 解密过程包装器
void aes256_dec_ecb_saes32(uint8_t pt[16], const uint8_t ct[16], const uint32_t rk[AES256_RK_WORDS])
{
	/*
	* 对密文（ct/128字节）使用秘钥（rk/60个扩展字）加密，输出解密后的明文（pt/128字节）
	* :param pt		:		明文，128字节
	* :param ct		:		密文，128字节
	* :param rk		:		扩展后的秘钥，60个扩展字（4 bytes/words）
	* :return (pt)	:		解密之后的结果，输出到pt/128字节
	*/
	aes_dec_rounds_saes32(pt, ct, rk, AES256_ROUNDS);
}

//  Helper: apply inverse mixcolumns to a vector

void saes32_dec_invmc(uint32_t* v, size_t len)
{
	size_t i;
	uint32_t x, y;

	for (i = 0; i < len; i++) {
		x = v[i];

		y = saes32_encs(0, x, 0);			//  SubWord()
		y = saes32_encs(y, x, 1);
		y = saes32_encs(y, x, 2);
		y = saes32_encs(y, x, 3);

		x = saes32_decsm(0, y, 0);			//  Just want inv MixCol()
		x = saes32_decsm(x, y, 1);
		x = saes32_decsm(x, y, 2);
		x = saes32_decsm(x, y, 3);

		v[i] = x;
	}
}

// AES-128解密过程的密钥扩展函数
void aes128_dec_key_saes32(uint32_t rk[44], const uint8_t key[16])
{
	//  create an encryption key and modify middle rounds
	aes128_enc_key(rk, key);
	saes32_dec_invmc(rk + 4, AES128_RK_WORDS - 8);
}

// AES-192解密过程的密钥扩展函数
void aes192_dec_key_saes32(uint32_t rk[52], const uint8_t key[24])
{
	//  create an encryption key and modify middle rounds
	aes192_enc_key(rk, key);
	saes32_dec_invmc(rk + 4, AES192_RK_WORDS - 8);
}

// AES-256解密过程的密钥扩展函数
void aes256_dec_key_saes32(uint32_t rk[60], const uint8_t key[32])
{
	//  create an encryption key and modify middle rounds
	aes256_enc_key(rk, key);
	saes32_dec_invmc(rk + 4, AES256_RK_WORDS - 8);
}
