/* ******************** RV-32 加密函数测试文档 ********************
* 工程主体： 山东大学
* 主工程文件： 闻乙名
*
* 创建日期：03.32.2020 8:50
* 主设计名称：RV32 加密函数测试文档
* 模块名称：RV32 比特操作/bit manipulation函数
*
* 关联文件：
* bitmanip.h			:		RV32 比特操作/bit manipulation函数（头文件）
*
* 说明：
*
**************************************************************** */
#include "bitmanip.h"

// 非进位乘法
uint32_t rv32b_clmul(uint32_t rs1, uint32_t rs2)		// PASS
{
	/*
	* 输入两个数据，依据小端格式进行两数相乘
	* :param rs1		:	第一个乘数（小端），0d17 = 0x00000011
	* :param rs2		:	第二个乘数（小端）, 0d5	 = 0x00000005
	* :return x			:	两数的乘积（小端）, 0d85 = 0x00000055
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
	* 输入两个数据，依据小端格式进行两数相乘（左右取反）
	* :param rs1		:	第一个乘数（小端取反），0d17 = 0x88000000
	* :param rs2		:	第二个乘数（小端取反）, 0d5	 = 0xA0000000
	* :return x			:	两数的乘积（小端取反）, 0d85 = 0xAA000000
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
	* 输入两个数据，求rs1循环右移rs2个单位以后的结果
	* :param rs1		:	被位移的数据		rs1 = 0x000ABCD0		rs1 = 0x000ABCD0
	* :param rs2		:	移动的位数			rs2 = 0x00000003		rs2 = 0x0000000A
	* :return 			:	循环移动后的结果	res = 0x0001579A		res = 0x340002AF
	*
	* 注：正常算法中第一个数据求非，本例中第二个数据求非
	*/
	int shamt = rs2 & (32 - 1);
	return (rs1 >> shamt) | (rs1 << ((32 - shamt) & (32 - 1)));
}

//  and with negate ANDN

uint64_t rv32b_andn(uint32_t rs1, uint32_t rs2)					// PASS
{
	/*
	* 输入两个数据，求两个数的按位与非值(32 bits)
	* :param rs1		:	第一个数据（不求非的那个）	rs1 = 0xCCCCCCCC
	* :param rs2		:	第二个数据（求非的那个）	rs2 = 0xAAAAAAAA, ~rs2 = 0x55555555
	* :return 			:	两个数据的与非值			res = 0x44444444
	*
	* 注：正常算法中第一个数据求非，本例中第二个数据求非
	*/
	return rs1 & ~rs2;
}

//  generalized reverse GREV / GREVI
uint32_t rv32b_grev(uint32_t rs1, uint32_t rs2)					// PASS
{
	/*
	* 输入一个数据，按照rs2给定的规则取反
	* :param rs1		:	被移位的数据												0x12ABCDEF
	* :param rs2		:	值为 0 - 31 中的一个值，超出范围不影响结果，取其前32个值	0b18
	* :return x			:	移位以后的结果												0xFEDCBA21
	*
	* 注：SHA2-256 中常用rs2 = 0x18 = 0b10010，即为按将数据按十六进制取逆
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

// Shuffle/Unshuffle函数帮助函数

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




