/* ******************** RV-32 加密函数测试文档 ********************
* 工程主体： 山东大学
* 主工程文件： 闻乙名
*
* 创建日期：03.3.2020 8:50
* 主设计名称：RV32 加密函数测试文档
* 模块名称：RV32 SM4加密测试顶层文件
*
* 关联文件：
*	sm4_wrap.h			:			SM4的包装函数
*
* 说明：
*
*
**************************************************************** */
#include "test_hex.h"
#include "sm4_wrap.h"


// SM4测试函数主函数
int test_sm4()
{
	uint8_t pt[16], ct[16], xt[16], key[16];										// pt: 明文，128字节；ct：密文，128字节；xt：解密明文，128字节；key：秘钥，最长256字节
	uint32_t rk[SM4_RK_WORDS];														// AES256加密，设定总字数为32个字
	int fail = 0;																	// 初始化报错个数

	// 测试1：SM4加解密
	readhex(key, sizeof(key), "0123456789ABCDEFFEDCBA9876543210");					// 密钥："0123456789ABCDEFFEDCBA9876543210"，共128位
	sm4_enc_key(rk, key);															// 秘钥扩展成32轮轮密钥（加密过程）
	readhex(pt, sizeof(pt), "0123456789ABCDEFFEDCBA9876543210");					// 明文："0123456789ABCDEFFEDCBA9876543210"，共128位
	// 加密过程
	sm4_enc_ecb(ct, pt, rk);
	fail += chkhex("SM4 Encrypt", ct, 16, "681EDF34D206965E86B3E94F536E4246");		// 加密过程验错
	// 解密过程
	sm4_dec_key(rk, key);															// 秘钥扩展成32轮轮密钥（解密过程）
	sm4_enc_ecb(xt, ct, rk);
	fail += chkhex("SM4 Decrypt", xt, 16, "0123456789ABCDEFFEDCBA9876543210");		// 解密过程验错

	// 测试2：SM4加解密
	readhex(key, sizeof(key), "FEDCBA98765432100123456789ABCDEF");					// 密钥："FEDCBA98765432100123456789ABCDEF"，共128位
	sm4_enc_key(rk, key);															// 秘钥扩展成32轮轮密钥（加密过程）
	readhex(pt, sizeof(pt), "000102030405060708090A0B0C0D0E0F");					// 明文："000102030405060708090A0B0C0D0E0F"，共128位
	// 加密过程
	sm4_enc_ecb(ct, pt, rk);
	fail += chkhex("SM4 Encrypt", ct, 16, "F766678F13F01ADEAC1B3EA955ADB594");		// 加密过程验错
	// 解密过程
	sm4_dec_key(rk, key);															// 秘钥扩展成32轮轮密钥（解密过程）
	sm4_dec_ecb(xt, ct, rk);
	fail += chkhex("SM4 Decrypt", xt, 16, "000102030405060708090A0B0C0D0E0F");		// 解密过程验错

	// 测试3：SM4加解密
	readhex(key, sizeof(key), "EB23ADD6454757555747395B76661C9A");
	sm4_enc_key(rk, key);
	readhex(pt, sizeof(pt), "D294D879A1F02C7C5906D6C2D0C54D9F");
	// 加密过程
	sm4_enc_ecb(ct, pt, rk);
	fail += chkhex("SM4 Encrypt", ct, 16, "865DE90D6B6E99273E2D44859D9C16DF");
	// 解密过程
	sm4_dec_key(rk, key);
	sm4_dec_ecb(xt, ct, rk);
	fail += chkhex("SM4 Decrypt", xt, 16, "D294D879A1F02C7C5906D6C2D0C54D9F");

	// 测试4：SM4加解密
	readhex(key, sizeof(key), "F11235535318FA844A3CBE643169F59E");
	sm4_enc_key(rk, key);
	readhex(pt, sizeof(pt), "A27EE076E48E6F389710EC7B5E8A3BE5");
	// 加密过程
	sm4_enc_ecb(ct, pt, rk);
	fail += chkhex("SM4 Encrypt", ct, 16, "94CFE3F59E8507FEC41DBE738CCD53E1");
	// 解密过程
	sm4_dec_key(rk, key);
	sm4_dec_ecb(xt, ct, rk);
	fail += chkhex("SM4 Decrypt", xt, 16, "A27EE076E48E6F389710EC7B5E8A3BE5");

	return fail;
}
