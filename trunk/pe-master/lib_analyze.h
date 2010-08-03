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
	char Name[16];      // 名称
	char Time[12];      // 时间
	char UserID[6];     // 用户ID
	char GroupID[6];    // 组ID
	char Mode[8];       // 模式
	char Size[10];      // 长度
	char EndOfHeader[2];// 结束符

} lib_section_hdr;

typedef struct __section1_data{
	unsigned long SymbolNum;         // 库中符号的数量
	unsigned long *SymbolOffset;   // 符号所在目标节的偏移
	char *StrTable;                // 符号名称字符串表
} section1_data;

typedef struct __section2_data{
	unsigned long ObjNum;        // Obj Sec的数量
	unsigned long *ObjOffset;  // 每一个Obj Sec的偏移
	unsigned long SymbolNum;     // 库中符号的数量
	unsigned short *SymbolIdx; // 符号在ObjOffset表中的索引
	char *StrTable;            // 符号名称字符串表
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