/* ******************** RV-32 ���ܺ��������ĵ� ********************
* �������壺 ɽ����ѧ
* �������ļ��� ������
*
* �������ڣ�03.32.2020 8:50
* ��������ƣ�RV32 ���ܺ��������ĵ�
* ģ�����ƣ�RV32 SM4��װ������ͷ�ļ���
*
* �����ļ���
* sm4_wrap.h			:		��װ���������ļ�
*
* ˵����
*
**************************************************************** */

#ifndef _SM4_WRAP_H_
#define _SM4_WRAP_H_

#include <stdint.h>

// SM4��Կ��չ���ִ�СΪ32����
#define SM4_RK_WORDS  32

// SM4�ӽ���ͨ�ú�����ʹ������Կ��������rk����
void sm4_encdec(uint8_t out[16], const uint8_t in[16], const uint32_t rk[SM4_RK_WORDS]);

// SM4���ܹ�����Կ��չ����
void sm4_enc_key(uint32_t rk[SM4_RK_WORDS], const uint8_t key[16]);

// SM4���ܹ�����Կ��չ����
void sm4_dec_key(uint32_t rk[SM4_RK_WORDS], const uint8_t key[16]);

// �����������壺��׼ģʽ��ΪECBģʽ
#define sm4_enc_ecb(ct, pt, rk) sm4_encdec(ct, pt, rk)
#define sm4_dec_ecb(pt, ct, rk) sm4_encdec(pt, ct, rk)

#endif // _SM4_WRAP_H_
