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

#define FUNC_CODE_FILLED_BYTE 0xcc
int find_next_func_code( byte *now_data, dword remain_size, byte **func_code, dword *code_size )
{
	int ret;
	int i;
	int filled_byte_finded;
	int next_func_finded;

	ret = 0;
	
	filled_byte_finded = FALSE;
	next_func_finded = FALSE;
	for( i = 0; i < remain_size; i ++ )
	{
		if( TRUE == filled_byte_finded )
		{
			if( FUNC_CODE_FILLED_BYTE == now_data[ i ] )
			{
				continue;
			}
			else
			{
				next_func_finded = TRUE;
				break;
			}


		}
		else
		{
			if( FUNC_CODE_FILLED_BYTE == now_data[ i ] )
			{
				filled_byte_finded = TRUE;
			}
		}
	}

	if( TRUE == next_func_finded )
	{
		*func_code = now_data + i;
		
		if( NULL != code_size )
		{
			byte *next_func;
			ret = find_next_func_code( now_data + i, remain_size - i, &next_func, NULL );
			if( 0 > ret )
			{
				next_func = now_data + remain_size;
			}

			ASSERT( NULL != next_func );
			*code_size = next_func - ( now_data + i );
		}
		return 0;
	}
	
	if( NULL != code_size )
	{
		*code_size = 0;
	}

	*func_code = NULL;

	return -1;
}

int find_cur_func_code( byte *now_data, dword remain_size, dword *code_size )
{
	int ret;
	int i;
	int filled_byte_finded;
	int next_func_finded;

	ret = 0;
	
	filled_byte_finded = FALSE;
	next_func_finded = FALSE;
	for( i = 0; i < remain_size; i ++ )
	{
		if( TRUE == filled_byte_finded )
		{
			if( FUNC_CODE_FILLED_BYTE == now_data[ i ] )
			{
				continue;
			}
			else
			{
				next_func_finded = TRUE;
				break;
			}
		}
		else
		{
			if( FUNC_CODE_FILLED_BYTE == now_data[ i ] )
			{
				filled_byte_finded = TRUE;
			}
		}
	}

	if( TRUE == next_func_finded )
	{
		*code_size = i;
		return 0;
	}

	*code_size = 0;

	return -1;
}


int find_func_code_start( byte *sect_data, dword sect_size, dword func_index, byte **func_code, dword *code_size )
{
	int ret = 0;
	int i;
	byte *next_func;
	byte *cur_func;
	dword __code_size;
	dword finded_size;

	cur_func = sect_data;
	finded_size = 0;

	if( 0 == func_index )
	{
		ret = find_cur_func_code( cur_func, sect_size - finded_size, &__code_size );
		if( 0 > ret )
		{
			__code_size = sect_size;
		}

		*func_code = cur_func;
		*code_size = __code_size;
		return 0;
	}

	for( i = 0; i < func_index; i ++ )
	{
		ret = find_cur_func_code( cur_func, sect_size - finded_size, &__code_size );
		if( 0 > ret )
		{
			return ret;
		}
		else
		{
			finded_size += __code_size;
			cur_func += __code_size;
		}
	}

	*func_code = cur_func;
	*code_size = __code_size;
	return ret;
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
	coff_ln_info *ln_info_table;
	coff_sym_ent *sym_ent_table;
	coff_sym_ent *sym_ent;
	coff_reloc *sect_relocs;
	coff_str_table *str_table;
	dword str_table_len;
	dword str_offset;
	char *string;
	char *sym_name;
	char *code_name;
	char *ln_sym_name;
	
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

		if( data + sect_hdr->sect_offset <= 0x00ba0e8d && data + sect_hdr->size + sect_hdr->sect_offset - 0x00ba0e80 > 0x18 )
		{
			int k = 10;
		}
#define STYP_TEXT 0x0020
#define STYP_DATA 0x0040
#define STYP_BSS 0x0080
		sect_hdr->flags;
		sect_hdr->ln_table_offset;
		sect_relocs = ( coff_reloc* )( data + sect_hdr->sect_rel_offset );
		ln_info_table = ( coff_ln_info* )( data + sect_hdr->ln_table_offset );

		for( j = 0; j < sect_hdr->ln_num; j ++ )
		{
			int ret;
			dword func_code_len;
			byte *func_code;
			ln_info_table[ j ].ln_no;

			ASSERT( ln_info_table[ j ].addr_symbol < file_hdr->syms_num );
			sym_ent = &sym_ent_table[ ln_info_table[ j ].addr_symbol ];

			if( 0 == sym_ent->sym_id.id.zero )
			{
				sym_name = ( byte* )str_table + sym_ent->sym_id.id.offset;
			}
			else
			{
				sym_name = sym_ent->sym_id.name;
			}

			if( sect_hdr->flags & STYP_TEXT )
			{
				ret = find_func_code_start( data + sect_hdr->sect_offset,sect_hdr->size, j, &func_code, &func_code_len );
				if( 0 > ret )
				{
					ASSERT( FALSE );
					continue;
				}

				if( NULL != analyzer->code_analyze )
				{
					code_infos code_info;
					code_info.func_code = func_code;
					code_info.func_code_len = func_code_len;
					code_info.func_name = sym_name;

					analyzer->code_analyze( &code_info, analyzer->context );
				}
			}
		}

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