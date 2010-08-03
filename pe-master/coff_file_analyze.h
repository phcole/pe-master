#ifndef __COFF_FILE_ANALYZE_H__
#define __COFF_FILE_ANALYZE_H__

#pragma pack( push )
#pragma pack( 1 )

typedef struct __coff_file_hdr{
  unsigned short magic;  // ħ������
  unsigned short sect_num;  // ���䣨Section����
  unsigned long  time;  // ʱ���
  unsigned long  syms_offset;  // ���ű�ƫ��
  unsigned long  syms_num;  // ������
  unsigned short opt_hdr_size;  // ��ѡͷ����
  unsigned short flags;  // �ļ����
} coff_file_hdr;

typedef struct __coff_opt_hdr28{
  unsigned short magic;  // ħ������
  unsigned short version;  // �汾��ʶ
  unsigned long  text_size;  // ���ģ�text���δ�С
  unsigned long  init_data_size;  // �ѳ�ʼ�����ݶδ�С
  unsigned long  uninit_data_size;  // δ��ʼ�����ݶδ�С
  unsigned long  entry;  // ��ڵ�
  unsigned long  text_base;  // ���Ķλ�ַ
  unsigned long  data_base;  // ���ݶλ�ַ����PE32�в��У�
} coff_opt_hdr28;


typedef struct __coff_sect_hdr{
  char           name[8];  // ����
  unsigned long  virt_size;  // �����С
  unsigned long  virt_addr;  // �����ַ
  unsigned long  size;  // �γ���
  unsigned long  sect_offset;  // ������ƫ��
  unsigned long  sect_rel_offset;  // ���ض�λ��ƫ��
  unsigned long  ln_table_offset;  // �кű�ƫ��
  unsigned short rel_offset_num;  // �ض�λ����
  unsigned short ln_num;  // �кű���
  unsigned long  flags;  // �α�ʶ
  //unsigned long reserved;
} coff_sect_hdr;

typedef struct __coff_reloc{
  unsigned long  ulAddr;  // ��λƫ��
  unsigned long  ulSymbol;  // ����
  unsigned short usType;  // ��λ����
} coff_reloc;

typedef struct {
    unsigned long addr_symbol;  // �����ַ���������
    unsigned short ln_no;  // �к�
} coff_ln_info;

typedef struct __coff_sym_ent{
  union {
    char name[8];            // ��������
    struct {
      unsigned long zero;   // �ַ������ʶ
      unsigned long offset; // �ַ���ƫ��
    } id;
  } sym_id;
  unsigned long value;     // ����ֵ
  short section;            // �������ڶ�
  unsigned short type;     // ��������
  unsigned char __class;     // ���Ŵ洢����
  unsigned char aux_num;    // ���Ÿ��Ӽ�¼��
} coff_sym_ent;

typedef struct __coff_str_table
{
	dword size;
	char strings[1];
} coff_str_table;
#pragma pack( pop )

#endif //__COFF_FILE_ANALYZE_H__