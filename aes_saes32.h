/* ******************** RV-32 加密函数测试文档 ********************
* 工程主体： 山东大学
* 主工程文件： 闻乙名
*
* 创建日期：03.32.2020 8:50
* 主设计名称：RV32 加密函数测试文档
* 模块名称：RV32 加密模块头文件（header）
*
* 关联文件：
* aes_saes32.c			:		加密函数的函数主体
*
* 说明：
*
*
**************************************************************** */

#ifndef _AES_SAES32_H_
#define _AES_SAES32_H_

#include <stdint.h>

// 加密秘钥产生过程
void aes128_enc_key_saes32(uint32_t rk[AES128_RK_WORDS], const uint8_t key[16]);
void aes192_enc_key_saes32(uint32_t rk[AES192_RK_WORDS], const uint8_t key[24]);
void aes256_enc_key_saes32(uint32_t rk[AES256_RK_WORDS], const uint8_t key[32]);

// 按消息块（block）加密信息
void aes128_enc_ecb_saes32(uint8_t ct[16], const uint8_t pt[16], const uint32_t rk[AES128_RK_WORDS]);

void aes192_enc_ecb_saes32(uint8_t ct[16], const uint8_t pt[16], const uint32_t rk[AES192_RK_WORDS]);

void aes256_enc_ecb_saes32(uint8_t ct[16], const uint8_t pt[16], const uint32_t rk[AES256_RK_WORDS]);


// 解密秘钥产生过程
void aes128_dec_key_saes32(uint32_t rk[AES128_RK_WORDS], const uint8_t key[16]);
void aes192_dec_key_saes32(uint32_t rk[AES192_RK_WORDS], const uint8_t key[24]);
void aes256_dec_key_saes32(uint32_t rk[AES256_RK_WORDS], const uint8_t key[32]);

// 按消息块（block）解密信息
void aes128_dec_ecb_saes32(uint8_t pt[16], const uint8_t ct[16], const uint32_t rk[AES128_RK_WORDS]);
void aes192_dec_ecb_saes32(uint8_t pt[16], const uint8_t ct[16], const uint32_t rk[AES192_RK_WORDS]);
void aes256_dec_ecb_saes32(uint8_t pt[16], const uint8_t ct[16], const uint32_t rk[AES256_RK_WORDS]);

#endif										//  _AES_SAES32_H_
