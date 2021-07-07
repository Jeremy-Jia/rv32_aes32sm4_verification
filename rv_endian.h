#ifndef _RV_ENDIAN_H_
#define _RV_ENDIAN_H_

// 如果数据格式不是大端存储，则进行调转
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define GREV_BE32(x) (x)
#else
	//  grev(x, 0x18) or rev8
#define GREV_BE32(x) (	\
	(((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8)  | \
	(((x) & 0x0000FF00) << 8)  | (((x) & 0x000000FF) << 24))
#endif


// 向左移位函数（32位）
static inline uint32_t rol32(uint32_t x, uint32_t n)
{
	/*
	* 将x向左循环移位n个比特
	* :param x		:		输入的字符
	* :param n		:		向左循环移位的位数
	* :return		:		将 x 向左循环移位 n 个比特后的结果
	*/
	return ((x) << n) | ((x) >> (32 - n));
}

// 小端存储与读取相关函数
static inline uint32_t get32u_le(const uint8_t* v)
{
	/*
	* 大端向小端格式转化
	* :param v		:		大端格式的输入数据，0x00, 0x01, 0x02, 0x03
	* :param v		:		按照小端格式输出，0x03020100
	*/

	// 第一个字（右起两位） | 第二个字（右起三四位） | 第三个字（右起五六位） | 第四个字（右起七八位）
	return ((uint32_t)v[0]) | (((uint32_t)v[1]) << 8) | (((uint32_t)v[2]) << 16) | (((uint32_t)v[3]) << 24);
}

static inline void put32u_le(uint8_t* v, uint32_t x)
{
	/*
	* 小端向大端格式转化(按字节数出)
	* :param x		:		小端格式的输入数据，0x03020100
	* :param v		:		按照大端格式输出，0x00,0x01,0x02,0x03
	*/
	v[0] = x;
	v[1] = x >> 8;
	v[2] = x >> 16;
	v[3] = x >> 24;
}




// 大端存储与读取相关函数
static inline uint32_t get32u_be(const uint8_t* v)
{
	/*
	* 小端向大端格式转化
	* :param v		:		小端格式的输入数据，0x03, 0x02, 0x01, 0x00
	* :param v		:		按照大端格式输出，0x00010203
	*/

	// 第一个字（右起两位） | 第二个字（右起三四位） | 第三个字（右起五六位） | 第四个字（右起七八位）
	return (((uint32_t)v[0]) << 24) | (((uint32_t)v[1]) << 16) | (((uint32_t)v[2]) << 8) | ((uint32_t)v[3]);
}

static inline void put32u_be(uint8_t* v, uint32_t x)
{
	/*
	* 大端向小端格式转化(按字节数出)
	* :param x		:		大端格式的输入数据，0x00010203
	* :param v		:		按照小端格式输出，0x03, 0x02, 0x01, 0x00
	*/
	v[0] = x >> 24;
	v[1] = x >> 16;
	v[2] = x >> 8;
	v[3] = x;
}

#endif
