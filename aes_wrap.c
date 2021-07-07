/* ******************** RV-32 加密函数测试文档 ********************
* 工程主体： 山东大学
* 主工程文件： 闻乙名
*
* 创建日期：03.32.2020 8:50
* 主设计名称：RV32 加密函数测试文档
* 模块名称：RV32 SM4包装函数
*
* 关联文件：
* sm4_wrap.h			:		包装函数函数文件（头文件）
*
* 说明：
*
**************************************************************** */
#include <stdio.h>
#include <stdlib.h>

#include "aes_wrap.h"				// 本函数对应的头文件
#include "aes_saes32.h"

static void key_undef(uint32_t* rk, const uint8_t* key)
{
	(void)rk;
	(void)key;

	fprintf(stderr, "[DEAD] key_undef()\n");
	abort();
}

static void ciph_undef(uint8_t* d, const uint8_t* s, const uint32_t* rk)
{
	(void)d;
	(void)s;
	(void)rk;

	fprintf(stderr, "[DEAD] key_undef()\n");
	abort();
}


// ===== 外部函数指针调用 =====
// 加密秘钥设置函数
void (*aes128_enc_key)(uint32_t rk[AES128_RK_WORDS], const uint8_t key[16]) = key_undef;
void (*aes192_enc_key)(uint32_t rk[AES192_RK_WORDS], const uint8_t key[24]) = key_undef;
void (*aes256_enc_key)(uint32_t rk[AES256_RK_WORDS], const uint8_t key[32]) = key_undef;

// ECB加密函数
void (*aes128_enc_ecb)(uint8_t ct[16], const uint8_t pt[16], const uint32_t rk[AES128_RK_WORDS]) = ciph_undef;
void (*aes192_enc_ecb)(uint8_t ct[16], const uint8_t pt[16], const uint32_t rk[AES192_RK_WORDS]) = ciph_undef;
void (*aes256_enc_ecb)(uint8_t ct[16], const uint8_t pt[16], const uint32_t rk[AES256_RK_WORDS]) = ciph_undef;

// 解密秘钥设置函数
void (*aes128_dec_key)(uint32_t rk[AES128_RK_WORDS], const uint8_t key[16]) = key_undef;
void (*aes192_dec_key)(uint32_t rk[AES192_RK_WORDS], const uint8_t key[24]) = key_undef;
void (*aes256_dec_key)(uint32_t rk[AES256_RK_WORDS], const uint8_t key[32]) = key_undef;

// ECB解密函数
void (*aes128_dec_ecb)(uint8_t pt[16], const uint8_t ct[16], const uint32_t rk[AES128_RK_WORDS]) = ciph_undef;
void (*aes192_dec_ecb)(uint8_t pt[16], const uint8_t ct[16], const uint32_t rk[AES192_RK_WORDS]) = ciph_undef;
void (*aes256_dec_ecb)(uint8_t pt[16], const uint8_t ct[16], const uint32_t rk[AES256_RK_WORDS]) = ciph_undef;
