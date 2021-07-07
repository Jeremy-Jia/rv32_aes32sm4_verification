#ifndef _SAES32_H_
#define _SAES32_H_

#include <stdint.h>

uint32_t saes32(uint32_t rs1, uint32_t rs2, int sn);				// RV32通用执行码（AES/SM4加解密指令集通用）

// AES加密指令集
uint32_t saes32_encsm(uint32_t rs1, uint32_t rs2, int bs);			// aes32esmi顶层函数
uint32_t saes32_encs(uint32_t rs1, uint32_t rs2, int bs);			// aes32esi顶层函数

// AES解密指令集
uint32_t saes32_decsm(uint32_t rs1, uint32_t rs2, int bs);			// aes32dsmi顶层函数
uint32_t saes32_decs(uint32_t rs1, uint32_t rs2, int bs);			// aes32dsi顶层函数

// SM4 相关
// SM4加解密指令集
uint32_t ssm4_ed(uint32_t rs1, uint32_t rs2, int bs);				// sm3ed顶层函数
// SM4秘钥扩展指令集
uint32_t ssm4_ks(uint32_t rs1, uint32_t rs2, int bs);				// sm4ks顶层函数
#endif //  _SAES32_H_

