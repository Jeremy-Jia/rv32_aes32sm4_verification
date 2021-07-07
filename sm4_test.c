/* ******************** RV-32 ���ܺ��������ĵ� ********************
* �������壺 ɽ����ѧ
* �������ļ��� ������
*
* �������ڣ�03.3.2020 8:50
* ��������ƣ�RV32 ���ܺ��������ĵ�
* ģ�����ƣ�RV32 SM4���ܲ��Զ����ļ�
*
* �����ļ���
*	sm4_wrap.h			:			SM4�İ�װ����
*
* ˵����
*
*
**************************************************************** */
#include "test_hex.h"
#include "sm4_wrap.h"


// SM4���Ժ���������
int test_sm4()
{
	uint8_t pt[16], ct[16], xt[16], key[16];										// pt: ���ģ�128�ֽڣ�ct�����ģ�128�ֽڣ�xt���������ģ�128�ֽڣ�key����Կ���256�ֽ�
	uint32_t rk[SM4_RK_WORDS];														// AES256���ܣ��趨������Ϊ32����
	int fail = 0;																	// ��ʼ���������

	// ����1��SM4�ӽ���
	readhex(key, sizeof(key), "0123456789ABCDEFFEDCBA9876543210");					// ��Կ��"0123456789ABCDEFFEDCBA9876543210"����128λ
	sm4_enc_key(rk, key);															// ��Կ��չ��32������Կ�����ܹ��̣�
	readhex(pt, sizeof(pt), "0123456789ABCDEFFEDCBA9876543210");					// ���ģ�"0123456789ABCDEFFEDCBA9876543210"����128λ
	// ���ܹ���
	sm4_enc_ecb(ct, pt, rk);
	fail += chkhex("SM4 Encrypt", ct, 16, "681EDF34D206965E86B3E94F536E4246");		// ���ܹ������
	// ���ܹ���
	sm4_dec_key(rk, key);															// ��Կ��չ��32������Կ�����ܹ��̣�
	sm4_enc_ecb(xt, ct, rk);
	fail += chkhex("SM4 Decrypt", xt, 16, "0123456789ABCDEFFEDCBA9876543210");		// ���ܹ������

	// ����2��SM4�ӽ���
	readhex(key, sizeof(key), "FEDCBA98765432100123456789ABCDEF");					// ��Կ��"FEDCBA98765432100123456789ABCDEF"����128λ
	sm4_enc_key(rk, key);															// ��Կ��չ��32������Կ�����ܹ��̣�
	readhex(pt, sizeof(pt), "000102030405060708090A0B0C0D0E0F");					// ���ģ�"000102030405060708090A0B0C0D0E0F"����128λ
	// ���ܹ���
	sm4_enc_ecb(ct, pt, rk);
	fail += chkhex("SM4 Encrypt", ct, 16, "F766678F13F01ADEAC1B3EA955ADB594");		// ���ܹ������
	// ���ܹ���
	sm4_dec_key(rk, key);															// ��Կ��չ��32������Կ�����ܹ��̣�
	sm4_dec_ecb(xt, ct, rk);
	fail += chkhex("SM4 Decrypt", xt, 16, "000102030405060708090A0B0C0D0E0F");		// ���ܹ������

	// ����3��SM4�ӽ���
	readhex(key, sizeof(key), "EB23ADD6454757555747395B76661C9A");
	sm4_enc_key(rk, key);
	readhex(pt, sizeof(pt), "D294D879A1F02C7C5906D6C2D0C54D9F");
	// ���ܹ���
	sm4_enc_ecb(ct, pt, rk);
	fail += chkhex("SM4 Encrypt", ct, 16, "865DE90D6B6E99273E2D44859D9C16DF");
	// ���ܹ���
	sm4_dec_key(rk, key);
	sm4_dec_ecb(xt, ct, rk);
	fail += chkhex("SM4 Decrypt", xt, 16, "D294D879A1F02C7C5906D6C2D0C54D9F");

	// ����4��SM4�ӽ���
	readhex(key, sizeof(key), "F11235535318FA844A3CBE643169F59E");
	sm4_enc_key(rk, key);
	readhex(pt, sizeof(pt), "A27EE076E48E6F389710EC7B5E8A3BE5");
	// ���ܹ���
	sm4_enc_ecb(ct, pt, rk);
	fail += chkhex("SM4 Encrypt", ct, 16, "94CFE3F59E8507FEC41DBE738CCD53E1");
	// ���ܹ���
	sm4_dec_key(rk, key);
	sm4_dec_ecb(xt, ct, rk);
	fail += chkhex("SM4 Decrypt", xt, 16, "A27EE076E48E6F389710EC7B5E8A3BE5");

	return fail;
}
