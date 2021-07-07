/* ******************** RV-32 加密函数测试文档 ********************
* 工程主体： 山东大学
* 主工程文件： 闻乙名
*
* 创建日期：03.32.2020 8:50
* 主设计名称：RV32 加密函数测试文档
* 模块名称：RV32 十六进制测试相关函数
*
* 相关文件：
*	test_hex.c		:		十六进制读取与转换测试代码
*
* 说明：
*
*
**************************************************************** */

#ifndef _TEST_HEX_H_
#define _TEST_HEX_H_

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// 读取一个字符串（str），其字符串长度为maxbytes，将其按照大端格式存储至buf
size_t readhex(uint8_t* buf, size_t maxbytes, const char* str);

// 对长度为（len），标签为（lab）的字符串（data），进行打印
void prthex(const char* lab, const void* data, size_t len);

// 检查数据长度为（len）的数据串（data）,对比的加解密函数标签为（lab），对应的比对结果为（*ref）
int chkhex(const char* lab, const void* data, size_t len, const char* ref);

// 如果加解密过程有错误，则输出错误的数据（测试标签lab，正确的比对结果want，实际产生的结果have）
int chkret(const char* lab, int want, int have);

#endif
