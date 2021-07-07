#ifndef _BITMANIP_H_
#define _BITMANIP_H_

#include <stdint.h>

// 向右循环移位
uint32_t rv32b_ror(uint32_t rs1, uint32_t rs2);

// 按位与非
uint64_t rv32b_andn(uint32_t rs1, uint32_t rs2);

// 通用调转函数
uint32_t rv32b_grev(uint32_t rs1, uint32_t rs2);

// 通用洗牌函数
uint32_t rv32b_shfl(uint32_t rs1, uint32_t rs2);

// 通用反洗牌函数
uint32_t rv32b_unshfl(uint32_t rs1, uint32_t rs2);

// 非进位乘法
uint32_t rv32b_clmul(uint32_t rs1, uint32_t rs2);
uint32_t rv32b_clmulh(uint32_t rs1, uint32_t rs2);
uint32_t rv32b_clmulr(uint32_t rs1, uint32_t rs2);

#endif //  _BITMANIP_H_
