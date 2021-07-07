/* ******************** RV-32 加密函数测试文档 ********************
* 工程主体： 山东大学
* 主工程文件： 闻乙名
*
* 创建日期：03.32.2020 8:50
* 主设计名称：RV32 加密函数测试文档
* 模块名称：RV32 SM4包装函数（头文件）
*
* 关联文件：
* sm4_wrap.h			:		包装函数函数文件
*
* 说明：
*
**************************************************************** */

#ifndef _SM4_WRAP_H_
#define _SM4_WRAP_H_

#include <stdint.h>

// SM4密钥扩展的字大小为32个字
#define SM4_RK_WORDS  32

// SM4加解密通用函数，使用轮密钥的轮数由rk决定
void sm4_encdec(uint8_t out[16], const uint8_t in[16], const uint32_t rk[SM4_RK_WORDS]);

// SM4加密过程密钥扩展函数
void sm4_enc_key(uint32_t rk[SM4_RK_WORDS], const uint8_t key[16]);

// SM4解密过程密钥扩展函数
void sm4_dec_key(uint32_t rk[SM4_RK_WORDS], const uint8_t key[16]);

// 函数别名定义：标准模式即为ECB模式
#define sm4_enc_ecb(ct, pt, rk) sm4_encdec(ct, pt, rk)
#define sm4_dec_ecb(pt, ct, rk) sm4_encdec(pt, ct, rk)

#endif // _SM4_WRAP_H_
