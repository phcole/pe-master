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

#include "common.h"
#include "common_analyze.h"
#include "lib_analyze.h"

#define LIB_FILE_HEADER "!<arch>\n"
#define STRTAB_END_SIGN "/\n"

void convert(void * p 
					,size_t size
					)
{
	int i;
	char * buf=(char*)p;
	char temp;
	for ( i=0;i<size/2;i++ ) {
		temp=buf[i];
		buf[i]=buf[size-i-1];
		buf[size-i-1]=temp;
	}
} 


int check_lib_file_header( byte *data, dword data_len )
{
	int ret;
	ASSERT( NULL != data );
	ASSERT( 0 <= data_len );

	if( CONST_STR_LEN( LIB_FILE_HEADER ) > data_len )
	{
		return -1;
	}

	ret = memcmp( data, LIB_FILE_HEADER, CONST_STR_LEN( LIB_FILE_HEADER ) );

	if( 0 != ret )
	{
		return -1;
	}

	return 0;
}

#define LIB_HDR_FILLED_BYTE 0x20
void clean_hdr_filled_bytes( lib_section_hdr *hdr )
{
	int i;
	byte *data;
	
	data = ( byte* )hdr;

	for( i = 0; i < sizeof( lib_section_hdr ); i ++ )
	{
		if( LIB_HDR_FILLED_BYTE == data[ i ] )
		{
			data[ i ] = 0;
		}
	}
}

typedef unsigned short word;
int read_lib_func_info( byte *data, dword data_len, coff_analyzer *analyzer )
{
	int ret = 0;
	byte *func_name_begin_dash;
	byte *func_name_begin_question;
	byte *func_name_begin;
	byte *func_name_end;
	lib_section_hdr *section1;
	lib_section_hdr *section2;
	dword sym_offset;
	char *sym_name;
	dword offset;

	byte *section1_data;
	byte *syms_offsets;
	byte *syms_str_table;
	dword syms_str_offset;
	dword syms_str_table_len;

	byte *section2_data;
	dword obj_sect_num;        // Obj Sec的数量
	dword *obj_sect_offset;  // 每一个Obj Sec的偏移
	dword syms_num;     // 库中符号的数量
	word *syms_idx; // 符号在ObjOffset表中的索引
	byte* section2_str_table;            // 符号名称字符串表
	dword section2_str_offset;
	dword section2_str_table_len;

	lib_section_hdr *long_name_sect;
	byte* long_name_str_table;            // 符号名称字符串表
	dword long_name_str_offset;
	dword long_name_str_table_len;

	lib_section_hdr *obj_file_sect;
	dword obj_file_name_offset;

	int i;

	ASSERT( NULL != data );
	ASSERT( 0 <= data_len );

	if( 0 == data_len )
	{
		ret = -1;
		goto __error;
	}

	offset = 0;

	ret = check_lib_file_header( data, data_len );
	if( 0 != ret )
	{
		ret = -1;
		goto __error;
	}

	offset += CONST_STR_LEN( LIB_FILE_HEADER );
	section1 = ( lib_section_hdr* )( data + offset );

	clean_hdr_filled_bytes( section1 );
	assert( 0 == strcmp( section1->Name, "/" ) );

	section1->Size;
	assert( 0 == memcmp( section1->EndOfHeader, LIB_SECT_HDR_END_SIGN, CONST_STR_LEN( LIB_SECT_HDR_END_SIGN ) ) );
	section1->Time;

	//typedef struct __section1_data{
	//	dword SymbolNum;         // 库中符号的数量
	//	dword *SymbolOffset;   // 符号所在目标节的偏移
	//	char *StrTable;                // 符号名称字符串表
	//} section1_data;
	offset += sizeof( lib_section_hdr );
	section1_data = data + offset;
	syms_num = *( dword* )section1_data;
	convert( &syms_num, sizeof( syms_num ) );
	offset += sizeof( dword );
	syms_offsets = data + offset;
	for( i = 0; i < syms_num; i ++ )
	{
		sym_offset = *( dword* )( syms_offsets );
		convert( &sym_offset, sizeof( sym_offset ) );
		syms_offsets += sizeof( dword );
	}

	offset += sizeof( dword ) * syms_num;
	syms_str_table = ( byte* )( data + offset );
	syms_str_table_len = atoi( section1->Size ) - ( sizeof( dword ) * syms_num + sizeof( dword ) );

	syms_str_offset = 0;
	for(;; )
	{
		syms_str_table;
		syms_str_offset += strlen( syms_str_table ) + sizeof( char );
		syms_str_table += strlen( syms_str_table ) + sizeof( char );
		
		assert( syms_str_offset <= syms_str_table_len );
		if( syms_str_offset == syms_str_table_len )
		{
			break;
		}
	}

	offset += syms_str_offset;

	section2 = ( lib_section_hdr* )( data + offset );
	if( 0 != memcmp( section1->EndOfHeader, LIB_SECT_HDR_END_SIGN, CONST_STR_LEN( LIB_SECT_HDR_END_SIGN ) ) )
	{
		offset += 1;
		section2 = ( lib_section_hdr* )data + offset;
	}

	section2->Size;
	section2->Time;
	section2->Name;

	clean_hdr_filled_bytes( section2 );

	assert( 0 == strcmp( section2->Name, "/" ) ); 

	offset += sizeof( lib_section_hdr );
	section2_data = data + offset;

	obj_sect_num = *( dword* )section2_data;
	offset += sizeof( dword );
	obj_sect_offset = data + offset;

	for( i = 0; i < obj_sect_num; i ++ )
	{
		obj_sect_offset[ i ];
	}

	offset += sizeof( dword ) * obj_sect_num;
	syms_num = *( dword* )( data + offset );

	offset += sizeof( dword );
	syms_idx = ( word* )( data + offset );

	for( i = 0; i < syms_num; i ++ )
	{
		syms_idx[ i ];
	}

	offset += sizeof( word ) * syms_num;
	section2_str_table = ( char* )( data + offset );

	section2_str_table_len = atoi( section2->Size )- ( ( obj_sect_num )* sizeof( dword ) + sizeof( dword ) + syms_num * sizeof( word ) + sizeof( dword ) );

	section2_str_offset = 0;
	for(;; )
	{
		section2_str_table;
		section2_str_offset += strlen( section2_str_table ) + sizeof( char );
		section2_str_table += strlen( section2_str_table ) + sizeof( char );

		assert( section2_str_offset <= section2_str_table_len );
		if( section2_str_offset == section2_str_table_len )
		{
			break;
		}
	}

	offset += section2_str_table_len;

	long_name_sect = ( lib_section_hdr* )( data + offset );
	offset += sizeof( lib_section_hdr );

	clean_hdr_filled_bytes( long_name_sect );
	if( 0 == strcmp( long_name_sect->Name, "//" ) )
	{
		long_name_str_table_len = atoi( long_name_sect->Size );
		long_name_str_table = ( char* )( data + offset );
		long_name_str_offset = 0;


		for( ; ; )
		{
			long_name_str_table;

			long_name_str_offset += strlen( long_name_str_table ) + 1;
			long_name_str_table += strlen( long_name_str_table ) + 1;
			
			assert( long_name_str_offset <= long_name_str_table_len );
			if( long_name_str_offset == long_name_str_table_len )
			{
				break;
			}
		}

		offset += atoi( long_name_sect->Size );
	}
	
	for( i = 0; i < obj_sect_num; i ++ )
	{
		obj_file_sect = ( lib_section_hdr* )( data + offset );
		
		clean_hdr_filled_bytes( obj_file_sect );

		if( obj_file_sect->Name[0] ==  '/' )
		{
			obj_file_name_offset = atoi( &obj_file_sect->Name[ 1 ] );
		}
		else
		{
			*strchr( obj_file_sect->Name, '/' ) = '\0';
		}

		analyze_coff_file( ( byte* )obj_file_sect + sizeof( lib_section_hdr ), analyzer );

		offset += sizeof( lib_section_hdr );
		offset += atoi( obj_file_sect->Size );
	}

		//for( i = 0; i < syms_num; i ++ )
	//{

	//}


#define remain_len( pointer ) ( dword )( data + data_len - pointer )
	
	func_name_begin = data;
	for( ; ; )
	{
		func_name_begin_question = memchr( func_name_begin, '?', remain_len( func_name_begin ) );
		func_name_begin_dash = memchr( func_name_begin, '_', remain_len( func_name_begin ) );

		if( func_name_begin_question != NULL && func_name_begin_dash > func_name_begin_question )
		{
			func_name_begin = func_name_begin_question;
		}
		else
		{
			func_name_begin = func_name_begin_dash;
		}

		if( NULL == func_name_begin )
		{
			break;
		}

		func_name_end = memchr( func_name_begin, 0, remain_len( func_name_begin ) );
		if( NULL == func_name_end )
		{
			break;
		}

		func_name_begin = func_name_end + sizeof( char );
	}

__error:
	return ret;
}

