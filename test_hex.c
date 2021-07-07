/* ******************** RV-32 加密函数测试文档 ********************
* 工程主体： 山东大学
* 主工程文件： 闻乙名
*
* 创建日期：03.32.2020 8:50
* 主设计名称：RV32 加密函数测试文档
* 模块名称：RV32 十六进制测试相关函数
*
* 相关文件：
*	test_hex.h		:		本文件相关的头文件函数定义
*
* 说明：
*
*
**************************************************************** */

#include "test_hex.h"

static int hexdigit(char ch)
{
	/*
	* 读取单个字符串，
	*/
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
	return -1;
}


size_t readhex(uint8_t * buf, size_t maxbytes, const char *str)
{
	/*
	* 从一个长度为（maxbytes）的字符串（*str）读取数据，返回转化以后的二进制信号
	* :param str		:		读入的字符串
	* :param maxbytes	:		读入字符串的字节长度
	* :return buf		:		字符串转化成的二进制信号
	*/
	size_t i;
	int h, l;

	for (i = 0; i < maxbytes; i++) {
		h = hexdigit(str[2 * i]);
		if (h < 0)
			return i;
		l = hexdigit(str[2 * i + 1]);
		if (l < 0)
			return i;
		buf[i] = (h << 4) + l;
	}

	return i;
}


void prthex(const char *lab, const void *data, size_t len)
{
	/*
	* 对长度为（len），标签为（lab）的字符串（data），进行打印
	* :param lab		:		测试的算法标签
	* :param data		:		待打印的字符串
	* :param len		:		字符串data的长度
	*/
	size_t i;
	uint8_t x;

	printf("[TEST] %s ", lab);
	const char hex[] = "0123456789ABCDEF";

	for (i = 0; i < len; i++) {
		x = ((const uint8_t *) data)[i];
		putchar(hex[(x >> 4) & 0xF]);
		putchar(hex[x & 0xF]);
	}
	putchar('\n');
}


int chkhex(const char *lab, const void *data, size_t len, const char *ref)
{
	/*
	* 检查数据长度为（len）的数据串（data）,对比的加解密函数标签为（lab），对应的比对结果为（*ref）
	* :param lab		:		测试的算法标签
	* :param data		:		待打印的字符串
	* :param len		:		字符串data的长度
	* :param ref		:		比对的参照字符串
	*/
	size_t i;
	uint8_t x;
	int fail = 0;

	// 按位比较内容
	for (i = 0; i < len; i++) {
		x = ((const uint8_t *) data)[i];
		if (hexdigit(ref[2 * i]) != ((x >> 4) & 0xF) ||
			hexdigit(ref[2 * i + 1]) != (x & 0x0F)) {
			fail = 1;
			break;
		}
	}

	// 比较字符串的长度
	if (i == len && hexdigit(ref[2 * len]) >= 0) {
		fail = 1;
	}

	printf("[%s] %s %s\n", fail ? "FAIL" : "PASS", lab, ref);

	if (fail) {
		prthex(lab, data, len);
	}

	return fail;
}


int chkret(const char *lab, int want, int have)
{
	/*
	* 如果加解密过程有错误，则输出错误的数据（测试标签lab，正确的比对结果want，实际产生的结果have）
	*/
	printf("[%s] %s WANT=%d  HAVE=%d\n",
		   want != have ? "FAIL" : "PASS", lab, want, have);

	return want != have ? 1 : 0;
}
