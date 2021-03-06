#include "test_hex.h"
#include "sha2_wrap.h"

//  SHA2-224/256

int test_sha2_256()
{	/*
	* 测试标的
	*/
	//  Padding tests
	const char* sha256_tv[][2] = {
		{ "",
		 "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855" },
		{ "3EBFB06DB8C38D5BA037F1363E118550AAD94606E26835A01AF05078533CC25F"
		 "2F39573C04B632F62F68C294AB31F2A3E2A1A0D8C2BE51",
		 "6595A2EF537A69BA8583DFBF7F5BEC0AB1F93CE4C8EE1916EFF44A93AF5749C4" },
		{ "2D52447D1244D2EBC28650E7B05654BAD35B3A68EEDC7F8515306B496D75F3E7"
		 "3385DD1B002625024B81A02F2FD6DFFB6E6D561CB7D0BD7A",
		 "CFB88D6FAF2DE3A69D36195ACEC2E255E2AF2B7D933997F348E09F6CE5758360" },
		{ "5A86B737EAEA8EE976A0A24DA63E7ED7EEFAD18A101C1211E2B3650C5187C2A8"
		 "A650547208251F6D4237E661C7BF4C77F335390394C37FA1A9F9BE836AC28509",
		 "42E61E174FBB3897D6DD6CEF3DD2802FE67B331953B06114A65C772859DFC1AA" },
		{ "451101250EC6F26652249D59DC974B7361D571A8101CDFD36ABA3B5854D3AE08"
		 "6B5FDD4597721B66E3C0DC5D8C606D9657D0E323283A5217D1F53F2F284F57B8"
		 "5C8A61AC8924711F895C5ED90EF17745ED2D728ABD22A5F7A13479A462D71B56"
		 "C19A74A40B655C58EDFE0A188AD2CF46CBF30524F65D423C837DD1FF2BF462AC"
		 "4198007345BB44DBB7B1C861298CDF61982A833AFC728FAE1EDA2F87AA2C9480"
		 "858BEC",
		 "3C593AA539FDCDAE516CDF2F15000F6634185C88F505B39775FB9AB137A10AA2" },
		{ NULL, NULL }
	};								// 测试标的，sha256tv(test vector)[i][0]: 测试中用到的输入
									//			 sha256tv(test vector)[i][1]: 测试中用到的输出

	uint8_t md[32], d[256];			// md 指代测试过程中生成的hash代码
	int fail = 0;
	int i;

	// 使用指定字母串作为测试SHA2_256(sha2_wrap.c)
	printf("[INFO] === SHA2_256 \"ABC\" test initialized ===\n");		// 使用ABC三个字母作为测试
	sha2_256(md, "abc", 3);												// sha2_wrap.c 计算输出（in = 3bytes）
	fail += chkhex("SHA2-256", md, 32,
		"BA7816BF8F01CFEA414140DE5DAE2223"
		"B00361A396177A9CB410FF61F20015AD");							// 检查 哈希运算的结果 md 与标准输出是否相同
	printf("[INFO] === SHA2_256 \"ABC\" test accomplished ===\n");


	// 使用指定字符串测试SHA2_224(sha2_wrap.c)，同时测试readhex函数（test_hex.c）
	printf("[INFO] === SHA2_224 \"determined input (10713B894DE4A734C0)\" test initialized ===\n");
	sha2_224(md, d, readhex(d, sizeof(d), "10713B894DE4A734C0"));		// 使用"10713B894DE4A734C0"计算输出
	fail += chkhex("SHA2-224", md, 28,
		"03842600C86F5CD60C3A2147A067CB96"
		"2A05303C3488B05CB45327BD");									// 检查 哈希运算的结果 md 与标准输出是否相同
	printf("[INFO] === SHA2_256 \"determined input\" test accomplished ===\n");

	// 使用本测试函数（test_sha2_256 - sha2_test.c）测试sha256
	printf("[INFO] === SHA2_224 \"determined input vector\" test initialized ===\n");
	for (i = 0; sha256_tv[i][0] != NULL; i++) {
		sha2_256(md, d, readhex(d, sizeof(d), sha256_tv[i][0]));		// 使用sha_256_tv[i][0]作为输入；注：d的值由 readhex函数直接写入
		fail += chkhex("SHA2-256", md, 32, sha256_tv[i][1]);			// 使用sha_256_tv[i][0]作为输出；
	}
	printf("[INFO] === SHA2_256 \"determined input vector\" test accomplished ===\n");

	return fail;
}

//  SHA2-384/512

int test_sha2_512()
{
	uint8_t md[64], d[256];
	size_t dlen;
	int fail = 0;

	//  使用指定字母串作为测试SHA2_512(sha2_wrap.c)
	printf("[INFO] === SHA2_512 \"abc\" test initialized ===\n");		// 使用ABC三个字母作为测试
	sha2_512(md, "abc", 3);												// sha2_wrap.c 计算输出（in = 3bytes）
	fail += chkhex("SHA2-512", md, 64,
		"DDAF35A193617ABACC417349AE204131"
		"12E6FA4E89A97EA20A9EEEE64B55D39A"
		"2192992A274FC1A836BA3C23A3FEEBBD"
		"454D4423643CE80E2A9AC94FA54CA49F");							// 检查 哈希运算的结果 md 与标准输出是否相同
	printf("[INFO] === SHA2_512 \"abc\" test accomplished ===\n");

	//  使用指定字符串测试SHA2_512(sha2_wrap.c)，同时测试readhex函数（test_hex.c）
	printf("[INFO] === SHA2_512 \"determined input \" test initialized ===\n");
	sha2_512(md, "abcdefghbcdefghicdefghijdefghijk"
				 "efghijklfghijklmghijklmnhijklmno"
				 "ijklmnopjklmnopqklmnopqrlmnopqrs" 
				 "mnopqrstnopqrstu", 112);								// sha2_512(output, input, length)
	fail += chkhex("SHA2-512", md, 64,
		"8E959B75DAE313DA8CF4F72814FC143F"
		"8F7779C6EB9F7FA17299AEADB6889018"
		"501D289E4900F7E4331B99DEC4B5433A"
		"C7D329EEB6DD26545E96E55B874BE909");
	printf("[INFO] === SHA2_512 \"determined input \" test accomplished ===\n");

	//  使用空白字符串测试SHA2_384(sha2_wrap.c)
	printf("[INFO] === SHA2_384 \"blank input \" test initialized ===\n");
	sha2_384(md, "", 0);												// sha2_512(output, input, length)
	fail += chkhex("SHA2-384", md, 48,
		"38B060A751AC96384CD9327EB1B1E36A"
		"21FDB71114BE07434C0CC7BF63F6E1DA"
		"274EDEBFE76F65FBD51AD2F14898B95B");
	printf("[INFO] === SHA2_384 \"blank input \" test accomplished ===\n");

	// 使用指定字符串测试SHA2_384(sha2_wrap.c)
	printf("[INFO] === SHA2_384 \"determinded input LONG \" test initialized ===\n");
	dlen = readhex(d, sizeof(d),
		"A04F390A9CC2EFFAD05DB80D9076A8D4"
		"B6CC8BBA97B27B423670B290B8E69C2B"
		"187230011C1481AC88D090F391546594"
		"94DB5E410851C6E8B2B8A93717CAE760"
		"37E0881978124FE7E1A0929D8891491F"
		"4E99646CC94062DC82411FA66130EDA4"
		"6560E75B98048236439465125E737B");
	sha2_384(md, d, dlen);
	fail += chkhex("SHA2-384", md, 48,
		"E7089D72945CEF851E689B4409CFB63D"
		"135F0B5CDFB0DAC6C3A292DD70371AB4"
		"B79DA1997D7992906AC7213502662920");
	printf("[INFO] === SHA2_384 \"determinded input LONG \" test accomplished ===\n");

	return fail;
}

//  HMAC tests

int test_sha2_hmac()
{
	uint8_t mac[64], k[256], d[256];
	size_t klen, dlen;
	int fail = 0;

	//  Test case 1 from RFC 4231
	// RFC 4231 提供了相应的测试案例
	printf("[INFO] === SHA2_224_HMAC \" RFC4231 \" test initialized ===\n");
	klen = readhex(k, sizeof(k),
		"0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B" "0B0B0B0B");					// HMAC所用的秘钥
	dlen = readhex(d, sizeof(d), "4869205468657265");					// 消息数据

	hmac_sha2_224(mac, k, klen, d, dlen);								// hmac_sha224(mac输出, 秘钥, 秘钥长度, 数据, 数据长度)
	fail += chkhex("HMAC-SHA2-224", mac, 28,
		"896FB1128ABBDF196832107CD49DF33F"
		"47B4B1169912BA4F53684B22");									// 检查hmac_sha224的结果是否满足条件
	printf("[INFO] === SHA2_224_HMAC \" RFC4231 \" test accomplished ===\n");

	hmac_sha2_256(mac, k, klen, d, dlen);
	fail += chkhex("HMAC-SHA2-256", mac, 32,
		"B0344C61D8DB38535CA8AFCEAF0BF12B"
		"881DC200C9833DA726E9376C2E32CFF7");

	hmac_sha2_384(mac, k, klen, d, dlen);
	fail += chkhex("HMAC-SHA2-384", mac, 48,
		"AFD03944D84895626B0825F4AB46907F"
		"15F9DADBE4101EC682AA034C7CEBC59C"
		"FAEA9EA9076EDE7F4AF152E8B2FA9CB6");

	hmac_sha2_512(mac, k, klen, d, dlen);
	fail += chkhex("HMAC-SHA2-512", mac, 64,
		"87AA7CDEA5EF619D4FF0B4241A1D6CB0"
		"2379F4E2CE4EC2787AD0B30545E17CDE"
		"DAA833B7D6B8A702038B274EAEA3F4E4"
		"BE9D914EEB61F1702E696C203A126854");


	//  Test case 2 from RFC 4231

	klen = readhex(k, sizeof(k), "4A656665");
	dlen = readhex(d, sizeof(d),
		"7768617420646F2079612077616E7420"
		"666F72206E6F7468696E673F");

	hmac_sha2_224(mac, k, klen, d, dlen);
	fail += chkhex("HMAC-SHA2-224", mac, 28,
		"A30E01098BC6DBBF45690F3A7E9E6D0F"
		"8BBEA2A39E6148008FD05E44");

	hmac_sha2_256(mac, k, klen, d, dlen);
	fail += chkhex("HMAC-SHA2-256", mac, 32,
		"5BDCC146BF60754E6A042426089575C7"
		"5A003F089D2739839DEC58B964EC3843");

	hmac_sha2_384(mac, k, klen, d, dlen);
	fail += chkhex("HMAC-SHA2-384", mac, 48,
		"AF45D2E376484031617F78D2B58A6B1B"
		"9C7EF464F5A01B47E42EC3736322445E"
		"8E2240CA5E69E2C78B3239ECFAB21649");

	hmac_sha2_512(mac, k, klen, d, dlen);
	fail += chkhex("HMAC-SHA2-512", mac, 64,
		"164B7A7BFCF819E2E395FBE73B56E0A3"
		"87BD64222E831FD610270CD7EA250554"
		"9758BF75C05A994A6D034F65F8F0E6FD"
		"CAEAB1A34D4A6B4B636E070A38BCE737");


	//  Test case 7 from RFC 4231 (multi-block key and data)

	klen = readhex(k, sizeof(k),
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "AAAAAA");
	dlen = readhex(d, sizeof(d),
		"54686973206973206120746573742075"
		"73696E672061206C6172676572207468"
		"616E20626C6F636B2D73697A65206B65"
		"7920616E642061206C61726765722074"
		"68616E20626C6F636B2D73697A652064"
		"6174612E20546865206B6579206E6565"
		"647320746F2062652068617368656420"
		"6265666F7265206265696E6720757365"
		"642062792074686520484D414320616C" "676F726974686D2E");

	hmac_sha2_224(mac, k, klen, d, dlen);
	fail += chkhex("HMAC-SHA2-224", mac, 28,
		"3A854166AC5D9F023F54D517D0B39DBD"
		"946770DB9C2B95C9F6F565D1");

	hmac_sha2_256(mac, k, klen, d, dlen);
	fail += chkhex("HMAC-SHA2-256", mac, 32,
		"9B09FFA71B942FCB27635FBCD5B0E944"
		"BFDC63644F0713938A7F51535C3A35E2");

	hmac_sha2_384(mac, k, klen, d, dlen);
	fail += chkhex("HMAC-SHA2-384", mac, 48,
		"6617178E941F020D351E2F254E8FD32C"
		"602420FEB0B8FB9ADCCEBB82461E99C5"
		"A678CC31E799176D3860E6110C46523E");

	hmac_sha2_512(mac, k, klen, d, dlen);
	fail += chkhex("HMAC-SHA2-512", mac, 64,
		"E37B6A775DC87DBAA4DFA9F96E5E3FFD"
		"DEBD71F8867289865DF5A32D20CDC944"
		"B6022CAC3C4982B10D5EEB55C3E4DE15"
		"134676FB6DE0446065C97440FA8C6A58");

	return fail;
}
