/* ******************** RV-32 加密函数测试文档 ********************
* 工程主体： 山东大学
* 主工程文件： 闻乙名
*
* 创建日期：03.5.2020 8:50
* 主设计名称：RV32 加密函数测试文档
* 模块名称：RV32秘钥扩展与加解密主体函数顶层包装函数（头文件）
*
* 关联文件：
*	aes_wrap.c			:		包装函数定义
*
* 说明：
*
*
**************************************************************** */

#ifndef _AES_WRAP_H_
#define _AES_WRAP_H_

#include <stdint.h>

// 加密轮数定义宏
#define AES128_ROUNDS 10				// AES-128加密，共10轮
#define AES192_ROUNDS 12				// AES-192加密，共12轮
#define AES256_ROUNDS 14				// AES-256加密，共14轮

// 秘钥扩展字数（每字4字节）
#define AES128_RK_WORDS (4 * (AES128_ROUNDS + 1))				// AES-128加密，共10轮，44个总字数
#define AES192_RK_WORDS (4 * (AES192_ROUNDS + 1))				// AES-192加密，共12轮，52个总字数
#define AES256_RK_WORDS (4 * (AES256_ROUNDS + 1))				// AES-256加密，共14轮，60个总字数

// 设定加密秘钥
extern void (*aes128_enc_key)(uint32_t rk[AES128_RK_WORDS], const uint8_t key[16]);			// AES-128：秘钥长度-128；字长度44 words
extern void (*aes192_enc_key)(uint32_t rk[AES192_RK_WORDS], const uint8_t key[24]);			// AES-192：秘钥长度-192；字长度52 words
extern void (*aes256_enc_key)(uint32_t rk[AES256_RK_WORDS], const uint8_t key[32]);			// AES-256：秘钥长度-256；字长度60 words

// 按照信息块（block）进行加密
extern void (*aes128_enc_ecb)(uint8_t ct[16], const uint8_t pt[16], const uint32_t rk[AES128_RK_WORDS]);	// AES-128：密文长度-128；明文长度-128；字长度44 words
extern void (*aes192_enc_ecb)(uint8_t ct[16], const uint8_t pt[16], const uint32_t rk[AES192_RK_WORDS]);	// AES-192：密文长度-128；明文长度-128；字长度52 words
extern void (*aes256_enc_ecb)(uint8_t ct[16], const uint8_t pt[16], const uint32_t rk[AES256_RK_WORDS]);	// AES-256：密文长度-128；明文长度-128；字长度60 words

// 设定解密秘钥
extern void (*aes128_dec_key)(uint32_t rk[AES128_RK_WORDS], const uint8_t key[16]);			// AES-128：秘钥长度-128；字长度44 words
extern void (*aes192_dec_key)(uint32_t rk[AES192_RK_WORDS], const uint8_t key[24]);			// AES-192：秘钥长度-192；字长度52 words
extern void (*aes256_dec_key)(uint32_t rk[AES256_RK_WORDS], const uint8_t key[32]);			// AES-256：秘钥长度-256；字长度60 words

// 按照信息块（block）进行解密
extern void (*aes128_dec_ecb)(uint8_t pt[16], const uint8_t ct[16], const uint32_t rk[AES128_RK_WORDS]);	// AES-128：密文长度-128；明文长度-128；字长度44 words
extern void (*aes192_dec_ecb)(uint8_t pt[16], const uint8_t ct[16], const uint32_t rk[AES192_RK_WORDS]);	// AES-192：密文长度-128；明文长度-128；字长度52 words
extern void (*aes256_dec_ecb)(uint8_t pt[16], const uint8_t ct[16], const uint32_t rk[AES256_RK_WORDS]);	// AES-256：密文长度-128；明文长度-128；字长度60 words

#endif										//  _AES_WRAP_H_
