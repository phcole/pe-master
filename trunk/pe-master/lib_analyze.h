/*
 * Copyright 2010 JiJie Shi
 *
 * This file is part of PEMaster.
 *
 * PEMaster is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * PEMaster is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PEMaster.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

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