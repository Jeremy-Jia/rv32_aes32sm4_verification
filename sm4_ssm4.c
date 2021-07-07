#include "sm4_wrap.h"
#include "saes32.h"
#include "rv_endian.h"

// ���ֽڽ����滻���ӽ����ֹ��̣�
#define SSM4_ED_X4(rs1, rs2) {		\
	rs1 = ssm4_ed(rs1, rs2, 0);		\
	rs1 = ssm4_ed(rs1, rs2, 1);		\
	rs1 = ssm4_ed(rs1, rs2, 2);		\
	rs1 = ssm4_ed(rs1, rs2, 3);		\
}

// ���ֽڽ����滻����Կ�������̣�
#define SSM4_KS_X4(rs1, rs2) {		\
	rs1 = ssm4_ks(rs1, rs2, 0);		\
	rs1 = ssm4_ks(rs1, rs2, 1);		\
	rs1 = ssm4_ks(rs1, rs2, 2);		\
	rs1 = ssm4_ks(rs1, rs2, 3);		\
}

//  encrypt or decrypt a block, depending on round key ordering

void sm4_encdec(uint8_t out[16], const uint8_t in[16], const uint32_t rk[SM4_RK_WORDS]){
	/*
	* ע�����½�����Լ��ܶ��ԣ��Խ��ܹ���ֱ�ӵ�ת����
	* ��SM4����ϵͳ�н�128λ���ģ�in������϶�Ӧ�ִ�����Կ��rk�������ܳ����������out��
	* :param out	:		���ܺ����������128λ
	* :param in		:		����ǰ�������룬128λ
	* :param rk		:		����ʹ�õ�����Կ
	*/
	uint32_t x0, x1, x2, x3;					// �����ֵ��м�ֵ
	uint32_t t, u;								// �м����
	const uint32_t* kp = &rk[SM4_RK_WORDS];		// �ӽ�������ֹ��

	x0 = get32u_le(in);						// ����ת��ΪС��
	x1 = get32u_le(in + 4);
	x2 = get32u_le(in + 8);
	x3 = get32u_le(in + 12);

	do {

		u = x2 ^ x3;						// X2 ^ X3
		t = rk[0];							// ���뵱ǰ�ֵ�����Կ	
		t ^= u;								// X2 ^ X3 ^ rk_i
		t ^= x1;							// X1 ^ X2 ^ X3 ^ rk_i
		SSM4_ED_X4(x0, t);					// S-box �ֽ��滻


		t = rk[1];							// ���뵱ǰ�ֵ�����Կ
											// u = X1 ^ X2
		t ^= u;								// X1 ^ X2 ^ rk_i
		t ^= x0;							// X1 ^ X2 ^ X3 ^ rk_i
		SSM4_ED_X4(x1, t);					// S-box �ֽ��滻
		
		u = x0 ^ x1;						// X2 ^ X3
		t = rk[2];							// ���뵱ǰ�ֵ�����Կ
		t ^= u;								// X2 ^ X3 ^ rk_i
		t ^= x3;							// X1 ^ X2 ^ X3 ^ rk_i
		SSM4_ED_X4(x2, t);					// S-box �ֽ��滻

		t = rk[3];							// ���뵱ǰ�ֵ�����Կ
											// u = X1 ^ X2
		t ^= u;								// X1 ^ X2 ^ rk_i
		t ^= x2;							// X1 ^ X2 ^ X3 ^ rk_i
		SSM4_ED_X4(x3, t);					// S-box �ֽ��滻

		rk += 4;							// ����Կָ��ǰ��

	} while (rk != kp);

	// ���ļӽ��ܽ���洢��out���ĸ�����Ҫǰ�����˳��
	put32u_le(out, x3);
	put32u_le(out + 4, x2);
	put32u_le(out + 8, x1);
	put32u_le(out + 12, x0);
}



void sm4_enc_key(uint32_t rk[SM4_RK_WORDS], const uint8_t key[16])
{
	/*
	* ��SM4����ϵͳ�н�128λ������Կ��չΪ32����չ��Կ��
	* :param key	:		key��ִ����չ֮ǰ����Կ��128λ
	* :param rk		:		round key����չ�Ժ������Կ��
	*/
	const uint32_t* kp = &rk[SM4_RK_WORDS];
	uint32_t x0, x1, x2, x3;				// ��Կ�������м���
	uint32_t t, u, ck;

	// ��Կ��ʼ��
	x0 = get32u_le(key);					// MK_0
	x1 = get32u_le(key + 4);				// MK_1
	x2 = get32u_le(key + 8);				// MK_2
	x3 = get32u_le(key + 12);				// MK_3

	// ��ʼ��K_0 - K_3
	x0 ^= 0xC6BAB1A3;						// K_0 = MK_0 ^ FK_0
	x1 ^= 0x5033AA56;						// K_1 = MK_1 ^ FK_1						
	x2 ^= 0x97917D67;						// K_2 = MK_2 ^ FK_2
	x3 ^= 0xDC2270B2;						// K_3 = MK_3 ^ FK_3

	ck = 0x140E0600;						// �̶�ȡֵCK_0������CK���㷨�����С�˴洢��

	do {
		/*
		* CK�Ĳ���������
		*	SM4�е�"CK"Ϊ��Կ���ɹ�����ʹ�õ�һ�ֳ��������������ǣ�
		*		1) ����� CK_i
		*		2) j Ϊ CK_i �ĵ� j �ֽ�(i = 0, 1, ..., 31; j = 0, 1, 2, 3)
		*		3) CK_j = (CK_i0, CK_i1, CK_i2, CK_i3)
		*		4) CK_ij = (4 * i + j ) * 7 (mod 256)
		*/
		t = ck ^ 0x01000100;				// t Ϊ��ȷ�ģ���������Կʹ�õ�ck
		ck += 0x1C1C1C1C;					// ��һ��ck�Ĳ�������
		ck &= 0xFEFEFEFE;					

		// K_i+1 ^ K_i+2 ^ K_i+3 ^ CK_i
		u = x2 ^ x3;						
		t = t ^ u;
		t = t ^ x1;
		SSM4_KS_X4(x0, t);					//  ִ��SM4_KS����

		rk[0] = x0;							// ��ʼ����Կ��չ�ռ䣬����ֵ����һ��rk0

		t = ck ^ 0x01000100;
		ck += 0x1C1C1C1C;
		ck &= 0xFEFEFEFE;

		t = t ^ u;
		t = t ^ x0;
		SSM4_KS_X4(x1, t);					
		rk[1] = x1;

		t = ck ^ 0x01000100;
		ck += 0x1C1C1C1C;
		ck &= 0xFEFEFEFE;

		u = x0 ^ x1;
		t ^= u;
		t ^= x3;
		SSM4_KS_X4(x2, t);					
		rk[2] = x2;

		t = ck ^ 0x01000100;
		ck += 0x1C1C1C1C;
		ck &= 0xFEFEFEFE;

		t ^= u;
		t ^= x2;
		SSM4_KS_X4(x3, t);					
		rk[3] = x3;

		rk += 4;

	} while (rk != kp);
}


void sm4_dec_key(uint32_t rk[SM4_RK_WORDS], const uint8_t key[16])
{
	/*
	* ��SM4����ϵͳ�н�128λ������Կ��չΪ32����չ��Կ��
	* :param key	:		key��ִ����չ֮ǰ����Կ��128λ
	* :param rk		:		round key����չ�Ժ������Կ��
	*/
	uint32_t t;
	int i, j;

	sm4_enc_key(rk, key);					//  ������Կʹ�ü�����Կ��չ����

	// ���ܹ���ʹ�ü�����Կ���е�������
	for (i = 0, j = SM4_RK_WORDS - 1; i < j; i++, j--) {
		t = rk[i];
		rk[i] = rk[j];
		rk[j] = t;
	}
}
