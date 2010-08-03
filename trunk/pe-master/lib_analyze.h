#ifndef __LIB_ANALYZE_H__
#define __LIB_ANALYZE_H__

#define LIB_SECT_HDR_END_SIGN "`\n"
typedef struct __lib_section_hdr
{
	char Name[16];      // ����
	char Time[12];      // ʱ��
	char UserID[6];     // �û�ID
	char GroupID[6];    // ��ID
	char Mode[8];       // ģʽ
	char Size[10];      // ����
	char EndOfHeader[2];// ������

} lib_section_hdr;

typedef struct __section1_data{
	unsigned long SymbolNum;         // ���з��ŵ�����
	unsigned long *SymbolOffset;   // ��������Ŀ��ڵ�ƫ��
	char *StrTable;                // ���������ַ�����
} section1_data;

typedef struct __section2_data{
	unsigned long ObjNum;        // Obj Sec������
	unsigned long *ObjOffset;  // ÿһ��Obj Sec��ƫ��
	unsigned long SymbolNum;     // ���з��ŵ�����
	unsigned short *SymbolIdx; // ������ObjOffset���е�����
	char *StrTable;            // ���������ַ�����
} section2_data;

#ifdef __cplusplus
extern "C" {
#endif

void convert(void * p, size_t size );
int find_section_2( byte *data );
int check_lib_file_header( byte *data, dword data_len );
int read_obj_section( lib_section_hdr* sect, byte *data );
int read_lib_func_info( byte *data, dword data_len, coff_analyzer *analyzer );

#ifdef __cplusplus
}
#endif

#endif