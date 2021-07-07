/* ******************** RV-32 ���ܺ��������ĵ� ********************
* �������壺 ɽ����ѧ
* �������ļ��� ������
*
* �������ڣ�03.32.2020 8:50
* ��������ƣ�RV32 ���ܺ��������ĵ�
* ģ�����ƣ�RV32 ���ز���/bit manipulation����
*
* �����ļ���
* bitmanip.h			:		RV32 ���ز���/bit manipulation������ͷ�ļ���
*
* ˵����
*
**************************************************************** */
#include "bitmanip.h"

// �ǽ�λ�˷�
uint32_t rv32b_clmul(uint32_t rs1, uint32_t rs2)		// PASS
{
	/*
	* �����������ݣ�����С�˸�ʽ�����������
	* :param rs1		:	��һ��������С�ˣ���0d17 = 0x00000011
	* :param rs2		:	�ڶ���������С�ˣ�, 0d5	 = 0x00000005
	* :return x			:	�����ĳ˻���С�ˣ�, 0d85 = 0x00000055
	*/
	uint32_t x = 0;
	for (int i = 0; i < 32; i++)
		if ((rs2 >> i) & 1)
			x ^= rs1 << i;
	return x;
}

uint32_t rv32b_clmulh(uint32_t rs1, uint32_t rs2)				// UT
{
	uint32_t x = 0;
	for (int i = 1; i < 32; i++)
		if ((rs2 >> i) & 1)
			x ^= rs1 >> (32 - i);
	return x;
}

uint32_t rv32b_clmulr(uint32_t rs1, uint32_t rs2)				// PASS
{
	/*
	* �����������ݣ�����С�˸�ʽ����������ˣ�����ȡ����
	* :param rs1		:	��һ��������С��ȡ������0d17 = 0x88000000
	* :param rs2		:	�ڶ���������С��ȡ����, 0d5	 = 0xA0000000
	* :return x			:	�����ĳ˻���С��ȡ����, 0d85 = 0xAA000000
	*/
	uint32_t x = 0;
	for (int i = 0; i < 32; i++)
		if ((rs2 >> i) & 1)
			x ^= rs1 >> (32 - i - 1);
	return x;
}

//  rotate right ROR / RORI

uint32_t rv32b_ror(uint32_t rs1, uint32_t rs2)				// PASS
{
	/*
	* �����������ݣ���rs1ѭ������rs2����λ�Ժ�Ľ��
	* :param rs1		:	��λ�Ƶ�����		rs1 = 0x000ABCD0		rs1 = 0x000ABCD0
	* :param rs2		:	�ƶ���λ��			rs2 = 0x00000003		rs2 = 0x0000000A
	* :return 			:	ѭ���ƶ���Ľ��	res = 0x0001579A		res = 0x340002AF
	*
	* ע�������㷨�е�һ��������ǣ������еڶ����������
	*/
	int shamt = rs2 & (32 - 1);
	return (rs1 >> shamt) | (rs1 << ((32 - shamt) & (32 - 1)));
}

//  and with negate ANDN

uint64_t rv32b_andn(uint32_t rs1, uint32_t rs2)					// PASS
{
	/*
	* �����������ݣ����������İ�λ���ֵ(32 bits)
	* :param rs1		:	��һ�����ݣ�����ǵ��Ǹ���	rs1 = 0xCCCCCCCC
	* :param rs2		:	�ڶ������ݣ���ǵ��Ǹ���	rs2 = 0xAAAAAAAA, ~rs2 = 0x55555555
	* :return 			:	�������ݵ����ֵ			res = 0x44444444
	*
	* ע�������㷨�е�һ��������ǣ������еڶ����������
	*/
	return rs1 & ~rs2;
}

//  generalized reverse GREV / GREVI
uint32_t rv32b_grev(uint32_t rs1, uint32_t rs2)					// PASS
{
	/*
	* ����һ�����ݣ�����rs2�����Ĺ���ȡ��
	* :param rs1		:	����λ������												0x12ABCDEF
	* :param rs2		:	ֵΪ 0 - 31 �е�һ��ֵ��������Χ��Ӱ������ȡ��ǰ32��ֵ	0b18
	* :return x			:	��λ�Ժ�Ľ��												0xFEDCBA21
	*
	* ע��SHA2-256 �г���rs2 = 0x18 = 0b10010����Ϊ�������ݰ�ʮ������ȡ��
	*/
	uint32_t x = rs1;
	int shamt = rs2 & 31;
	if (shamt & 1)
		x = ((x & 0x55555555) << 1) | ((x & 0xAAAAAAAA) >> 1);
	if (shamt & 2)
		x = ((x & 0x33333333) << 2) | ((x & 0xCCCCCCCC) >> 2);
	if (shamt & 4)
		x = ((x & 0x0F0F0F0F) << 4) | ((x & 0xF0F0F0F0) >> 4);
	if (shamt & 8)
		x = ((x & 0x00FF00FF) << 8) | ((x & 0xFF00FF00) >> 8);
	if (shamt & 16)
		x = ((x & 0x0000FFFF) << 16) | ((x & 0xFFFF0000) >> 16);
	return x;
}

// Shuffle/Unshuffle������������

static inline uint32_t shuffle32_stage(uint32_t src, uint32_t ml,
	uint32_t mr, int n)
{
	uint32_t x = src & ~(ml | mr);
	x |= ((src << n) & ml) | ((src >> n) & mr);
	return x;
}


uint32_t rv32b_shfl(uint32_t rs1, uint32_t rs2)
{
	uint32_t x = rs1;
	int shamt = rs2 & 15;

	if (shamt & 8)
		x = shuffle32_stage(x, 0x00FF0000, 0x0000FF00, 8);
	if (shamt & 4)
		x = shuffle32_stage(x, 0x0F000F00, 0x00F000F0, 4);
	if (shamt & 2)
		x = shuffle32_stage(x, 0x30303030, 0x0C0C0C0C, 2);
	if (shamt & 1)
		x = shuffle32_stage(x, 0x44444444, 0x22222222, 1);

	return x;
}


uint32_t rv32b_unshfl(uint32_t rs1, uint32_t rs2)
{
	uint32_t x = rs1;
	int shamt = rs2 & 15;

	if (shamt & 1)
		x = shuffle32_stage(x, 0x44444444, 0x22222222, 1);
	if (shamt & 2)
		x = shuffle32_stage(x, 0x30303030, 0x0C0C0C0C, 2);
	if (shamt & 4)
		x = shuffle32_stage(x, 0x0F000F00, 0x00F000F0, 4);
	if (shamt & 8)
		x = shuffle32_stage(x, 0x00FF0000, 0x0000FF00, 8);

	return x;
}



uint32_t pack(uint32_t rs1, uint32_t rs2)
{
	uint32_t lower = (rs1 << 16) >> 16;
	uint32_t upper = (rs2 << 16) << 16;

	return lower | upper;
}


uint32_t packu(uint32_t rs1, uint32_t rs2)
{
	uint32_t lower = rs1 >> 16;
	uint32_t upper = (rs2 >> 16) << 16;

	return lower | upper;
}

uint32_t packh(uint32_t rs1, uint32_t rs2)
{
	uint32_t lower = rs1 & 255;
	uint32_t upper = (rs2 & 255) << 8;

	return lower | upper;
}




