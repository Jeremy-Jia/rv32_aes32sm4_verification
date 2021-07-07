/* ******************** RV-32 加密函数测试文档 ********************
* 工程主体： 山东大学
* 主工程文件： 闻乙名
*
* 创建日期：03.32.2020 8:50
* 主设计名称：RV32 加密函数测试文档
* 模块名称：S-boxes（AES与SM4用）
*
* 关联文件：
* sboxes.c			:		AES与SM4调用的S-box
*
* 说明：
*	1) AES加解密使用的S-box不同
*   2) SM4加解密使用的S-box相同
*
**************************************************************** */

#ifndef _SBOXES_H_
#define _SBOXES_H_

#include <stdint.h>

// AES使用的轮常数 
extern const uint8_t aes_rcon[];

// AES加密过程使用的S-box
extern const uint8_t aes_sbox[256];

// AES解密过程使用的S-box
extern const uint8_t aes_isbox[256];

// AES加解密过程使用的S-box
// 注：加解密过程使用的S-box相同
extern const uint8_t sm4_sbox[256];

#endif // _SBOXES_H_

