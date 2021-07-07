/* ******************** RV-32 加密函数测试文档 ********************
* 工程主体： 山东大学
* 主工程文件： 闻乙名
*
* 创建日期：03.3.2020 8:50
* 主设计名称：RV32 加密函数测试文档
* 模块名称：RV32 AES加密测试顶层文件
*
* 关联文件：
* 	aes_wrap.h		:		AES顶层函数包装函数
*
* 说明：
*
*
**************************************************************** */

#include "test_hex.h"
#include "aes_wrap.h"

//  Test AES

int test_aes()
{
	uint8_t pt[16], ct[16], xt[16], key[32];					// pt: 明文，128字节；ct：密文，128字节；xt：解密明文，128字节；key：秘钥，最长256字节
	uint32_t rk[AES256_RK_WORDS];								// AES256加密，设定总字数为60个字
	int fail = 0;												// 初始化报错个数

	// 根据FIPS197进行测试
	// 测试1：AES-128加解密
	readhex(pt, sizeof(pt), "00112233445566778899AABBCCDDEEFF");										// 明文："00112233445566778899AABBCCDDEEFF"，共128位
	readhex(key, sizeof(key), "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");		// 秘钥：共256位
	// 加密过程
	aes128_enc_key(rk, key);				// 使用初始秘钥进行秘钥扩展		key --> round_key
	aes128_enc_ecb(ct, pt, rk);				// 使用扩展秘钥进行加密			plaintext + round_key => ciphertext
	fail += chkhex("AES-128 Enc", ct, 16, "69C4E0D86A7B0430D8CDB78070B4C55A");							// AES-128加密过程检查。若出现错误，则返回+1
	// 解密过程
	aes128_dec_key(rk, key);				// 使用初始秘钥进行秘钥扩展		key --> round_key
	aes128_dec_ecb(xt, ct, rk);				// 使用扩展秘钥进行加密			plaintext + round_key => ciphertext
	fail += chkhex("AES-128 Dec", xt, 16, "00112233445566778899AABBCCDDEEFF");							// AES-128解密过程检查。若出现错误，则返回+1

	// 测试2：AES-192加解密
	// 加密过程
	aes192_enc_key(rk, key);
	aes192_enc_ecb(ct, pt, rk);
	fail += chkhex("AES-192 Enc", ct, 16, "DDA97CA4864CDFE06EAF70A0EC0D7191");
	// 解密过程
	aes192_dec_key(rk, key);
	aes192_dec_ecb(xt, ct, rk);
	fail += chkhex("AES-192 Dec", xt, 16, "00112233445566778899AABBCCDDEEFF");

	// 测试3：AES-256加解密
	// 加密过程
	aes256_enc_key(rk, key);
	aes256_enc_ecb(ct, pt, rk);
	fail += chkhex("AES-256 Enc", ct, 16, "8EA2B7CA516745BFEAFC49904B496089");
	// 解密过程
	aes256_dec_key(rk, key);
	aes256_dec_ecb(xt, ct, rk);
	fail += chkhex("AES-256 Dec", xt, 16, "00112233445566778899AABBCCDDEEFF");




	// **************** 华丽丽的分隔符 ****************
	// 第二组测试过程
	// 测试1：AES-128加解密
	readhex(pt, sizeof(pt), "6BC1BEE22E409F96E93D7E117393172A");
	readhex(key, sizeof(key), "2B7E151628AED2A6ABF7158809CF4F3C");
	// 加密过程
	aes128_enc_key(rk, key);
	aes128_enc_ecb(ct, pt, rk);
	fail += chkhex("AES-128 Enc", ct, 16, "3AD77BB40D7A3660A89ECAF32466EF97");
	// 解密过程
	aes128_dec_key(rk, key);
	aes128_dec_ecb(xt, ct, rk);
	fail += chkhex("AES-128 Dec", xt, 16, "6BC1BEE22E409F96E93D7E117393172A");

	// 测试2：AES-192加解密
	readhex(pt, sizeof(pt), "AE2D8A571E03AC9C9EB76FAC45AF8E51");
	readhex(key, sizeof(key), "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B");
	// 加密过程
	aes192_enc_key(rk, key);
	aes192_enc_ecb(ct, pt, rk);
	fail += chkhex("AES-192 Enc", ct, 16, "974104846D0AD3AD7734ECB3ECEE4EEF");
	// 解密过程
	aes192_dec_key(rk, key);
	aes192_dec_ecb(xt, ct, rk);
	fail += chkhex("AES-192 Dec", xt, 16, "AE2D8A571E03AC9C9EB76FAC45AF8E51");

	// 测试3：AES-256加解密
	readhex(pt, sizeof(pt), "30C81C46A35CE411E5FBC1191A0A52EF");
	readhex(key, sizeof(key), "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4");
	// 加密过程
	aes256_enc_key(rk, key);
	aes256_enc_ecb(ct, pt, rk);
	fail += chkhex("AES-256 Enc", ct, 16, "B6ED21B99CA6F4F9F153E7B1BEAFED1D");
	// 解密过程
	aes256_dec_key(rk, key);
	aes256_dec_ecb(xt, ct, rk);
	fail += chkhex("AES-256 Dec", xt, 16, "30C81C46A35CE411E5FBC1191A0A52EF");

	return fail;
}
