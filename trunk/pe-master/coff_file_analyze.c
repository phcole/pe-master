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
#include "coff_file_analyze.h"

#define I386_COFF_FILE_MAGIC 0x014c
#define F_RELFLG 0x0001
#define F_EXEC 0x0002
#define F_LNNO 0x0004
#define F_LSYMS 0x0008
#define F_AR32WR 0x0100

dword get_sym_data_len( coff_reloc *relocs, dword cur_reloc_index, dword reloc_count, coff_sect_hdr *hdr )
{
	dword sym_data_len = 0;

	return sym_data_len;
}

int analyze_coff_file( byte *data, coff_analyzer *analyzer )
{
	int i;
	int j;
	coff_file_hdr *file_hdr;
	coff_sect_hdr *sect_hdr;
	byte *opt_hdr;
	byte *sym_data;
	dword sym_data_len;
	dword opt_hdr_len;
	dword offset;
	coff_sym_ent *sym_ent_table;
	coff_sym_ent *sym_ent;
	coff_reloc *sect_relocs;
	coff_str_table *str_table;
	dword str_table_len;
	dword str_offset;
	char *string;
	char *sym_name;
	
	offset = 0;
	file_hdr = ( coff_file_hdr* )data + offset;

	assert( I386_COFF_FILE_MAGIC == file_hdr->magic );

	file_hdr->time;
	file_hdr->sect_num;
	file_hdr->syms_num;
	file_hdr->syms_offset;

	sym_ent_table = data + file_hdr->syms_offset;

	str_table = ( coff_str_table*)( ( byte* )sym_ent_table + sizeof( coff_sym_ent ) * file_hdr->syms_num );
	str_table->size;

	offset += sizeof( coff_file_hdr );
	opt_hdr_len = file_hdr->opt_hdr_size;
	if( 28 == opt_hdr_len )
	{
		coff_opt_hdr28 *opt_hdr28;
		opt_hdr28 = ( coff_opt_hdr28* )( data + offset );
		opt_hdr28->magic == 0x010b; //exe
		opt_hdr28->magic == 0x0107; //rom 
		opt_hdr28->entry;
		opt_hdr28->version;
		opt_hdr28->text_base;
	}

	offset += opt_hdr_len;
	//.text£¬.data£¬.comment£¬.bss

	for( i = 0; i < file_hdr->sect_num; i ++ )
	{
		sect_hdr = ( coff_sect_hdr* )( data + offset );

#define STYP_TEXT 0x0020
#define STYP_DATA 0x0040
#define STYP_BSS 0x0080
		sect_hdr->flags;
		sect_hdr->ln_table_offset;
		sect_relocs = ( coff_reloc* )( data + sect_hdr->sect_rel_offset );

		for( j = 0; j < sect_hdr->rel_offset_num; j ++ )
		{
#define RELOC_ADDR32 6
#define RELOC_REL32 20 

			sym_data = ( data + sect_relocs[ j ].ulAddr + sect_hdr->sect_offset );
			
			sym_data_len = get_sym_data_len( sect_relocs, j, sect_hdr->rel_offset_num, sect_hdr );

			ASSERT( sect_relocs[ j ].ulSymbol < file_hdr->syms_num );

			sym_ent = &sym_ent_table[ sect_relocs[ j ].ulSymbol ];

			if( 0 == sym_ent->sym_id.id.zero )
			{
				sym_name = ( byte* )str_table + sym_ent->sym_id.id.offset;
			}
			else
			{
				sym_name = sym_ent->sym_id.name;
			}

			if( NULL != analyzer )
			{
				if( NULL != analyzer->syms_analyze )
				{
					sym_infos sym_info;
					sym_info.sym_data = sym_data;
					sym_info.sym_data_len = sym_data_len;
					sym_info.sym_name = sym_name;

					analyzer->syms_analyze( &sym_info, analyzer->context );
				}
			}
			sect_relocs->usType;
	
#define SYM_PTR_TYPE 0x01
#define SYM_FUNC_TYPE 0x02 
#define SYM_ARRAY_TYPE 0x03
#define SYM_NONE_TYPE 0x00


#define SYM_NONE_STORE_TYPE 0
#define SYM_AUTOMATIC_STORE_TYPE 1
#define SYM_EXTERNAL_STORE_TYPE 2
#define SYM_STATIC_STORE_TYPE 3 //offset 0 is the section name
#define SYM_REGISTER_STORE_TYPE 4
#define SYM_MEMBER_OF_STRUCT_STORE_TYPE 8
#define SYM_STRUCT_TAG_STORE_TYPE 10
#define SYM_MEMBER_OF_UNION_STORE_TYPE 11 //value is order of symbol in the enum
#define SYM_UNION_TAG_STORE_TYPE 12
#define SYM_TYPE_DEFINITION_STORE_TYPE 13
#define SYM_FUNCTION_STORE_TYPE 13
#define SYM_FILE_STORE_TYPE 13

			sym_ent->aux_num == 1; //next sym is the aux info of cur sym.the cont of it is affected with type of the data in it.
		}
		offset += sizeof( coff_sect_hdr );
	}

	string = str_table->strings;
	str_table_len = str_table->size - sizeof( dword );
	str_offset = 0;

	for(; ; )
	{
		string;
		str_offset += strlen( string ) + sizeof( char );
		string += strlen( string ) + sizeof( char );

		if( NULL != analyzer->strs_analyze )
		{
			sym_infos sym_info;
			sym_info.sym_data = NULL;
			sym_info.sym_data_len = 0;
			sym_info.sym_name = string;

			analyzer->strs_analyze( &sym_info, analyzer->context );
		}
		assert( str_offset <= str_table_len );
		if( str_offset == str_table_len )
		{
			break;
		}
	}
}