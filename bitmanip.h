#ifndef _BITMANIP_H_
#define _BITMANIP_H_

#include <stdint.h>

// ����ѭ����λ
uint32_t rv32b_ror(uint32_t rs1, uint32_t rs2);

// ��λ���
uint64_t rv32b_andn(uint32_t rs1, uint32_t rs2);

// ͨ�õ�ת����
uint32_t rv32b_grev(uint32_t rs1, uint32_t rs2);

// ͨ��ϴ�ƺ���
uint32_t rv32b_shfl(uint32_t rs1, uint32_t rs2);

// ͨ�÷�ϴ�ƺ���
uint32_t rv32b_unshfl(uint32_t rs1, uint32_t rs2);

// �ǽ�λ�˷�
uint32_t rv32b_clmul(uint32_t rs1, uint32_t rs2);
uint32_t rv32b_clmulh(uint32_t rs1, uint32_t rs2);
uint32_t rv32b_clmulr(uint32_t rs1, uint32_t rs2);

#endif //  _BITMANIP_H_
