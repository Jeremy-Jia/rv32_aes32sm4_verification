/* ******************** RV-32 加密函数测试文档 ********************

* 模块名称：RV32 测试顶层文件
*
* 依赖文件：
* aes_wrap.h			: aes
* saes32.h				:
* aes_saes32.h			:
* 
* 说明：
*
**************************************************************** */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>


//#include "bitmanip.h"					// 比特操作函数
//#include "sha2_wrap.h"


#include "aes_wrap.h"
#include "saes32.h"
#include "aes_saes32.h"


//  调用测试特定模块需要预先加载函数主体
int test_aes();								//  调用文件：aes_test.c
int test_sm4();								//  调用文件：sm4_test.c


int main(int argc, char** argv)
{
	int fail = 0;

	// 算法测试过程
	printf("[INFO] ====== RV32 简单AES加密 （ECB模式） ======\n");
	printf("[INFO] === RV32 Simple AES Cryptography (ECB) ===\n");

	aes128_enc_key = aes128_enc_key_saes32;				// AES-128加密：加密秘钥扩展函数
	aes192_enc_key = aes192_enc_key_saes32;				// AES-192加密：加密秘钥扩展函数
	aes256_enc_key = aes256_enc_key_saes32;				// AES-256加密：加密秘钥扩展函数

	aes128_enc_ecb = aes128_enc_ecb_saes32;				// AES-128加密：ECB模式，块加密函数		
	aes192_enc_ecb = aes192_enc_ecb_saes32;				// AES-192加密：ECB模式，块加密函数	
	aes256_enc_ecb = aes256_enc_ecb_saes32;				// AES-256加密：ECB模式，块加密函数	

	aes128_dec_key = aes128_dec_key_saes32;				// AES-128加密：解密秘钥扩展函数	
	aes192_dec_key = aes192_dec_key_saes32;				// AES-192加密：解密秘钥扩展函数
	aes256_dec_key = aes256_dec_key_saes32;				// AES-256加密：解密秘钥扩展函数

	aes128_dec_ecb = aes128_dec_ecb_saes32;				// AES-128加密：ECB模式，块解密函数	
	aes192_dec_ecb = aes192_dec_ecb_saes32;				// AES-192加密：ECB模式，块解密函数	
	aes256_dec_ecb = aes256_dec_ecb_saes32;				// AES-256加密：ECB模式，块解密函数	

	fail += test_aes();						// AES 加解密测试

	printf("[INFO] === SM4 test ===\n");
	fail += test_sm4();						// SM4 加解密测试

	if (fail == 0) {
		printf("[PASS] all tests passed.\n");
	}
	else {
		printf("[FAIL] %d test(s) failed.\n", fail);
	}

	printf("********test aes32esmi*********\n");
	uint32_t a1 = 1, b1 = 0;
	b1= saes32_encsm(a1, a1, 1);
	printf("b1 = %d\n", b1);

	printf("********test aes32esi*********\n");
	uint32_t a2 = 1, b2 = 0;
	b2 = saes32_encs(a2, a2, 1);
	printf("b2 = %d\n", b2);

	printf("********test aes32dsmi*********\n");
	uint32_t a3 = 1, b3 = 0;
	b3 = saes32_decsm(a3, a3, 1);
	printf("b3 = %d\n", b3);

	printf("********test aes32dsi*********\n");
	uint32_t a4 = 1, b4 = 0;
	b4 = saes32_decs(a4, a4, 1);
	printf("b4 = %d\n", b4);
		
	printf("********test sm4ed*********\n");
	uint32_t a5 = 1, b5 = 0;
	b5 = ssm4_ed(a5,a5,1);
	printf("b5 = %d\n", b5);
	
	printf("********test sm4ks*********\n");
	uint32_t a6 = 1, b6 = 0;
	b6 = ssm4_ks(a6, a6, 1);
	printf("b6 = %d\n", b6);


	return fail;
}
