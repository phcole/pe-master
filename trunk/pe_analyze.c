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
#include "pe_analyze.h"

#define MAX_MSG_LEN 512
INT32 ErrorHandle( DWORD dwErrorCode )
{
	DWORD dwLastError;
	CHAR szMsg[ MAX_MSG_LEN ];

	dwLastError = GetLastError();
}

PBYTE find_virt_addr_ptr2( DWORD virt_addr, DWORD size, PIMAGE_SECTION_HEADER sect_hdrs, DWORD sect_num, PBYTE data, PIMAGE_SECTION_HEADER *finded_sect )
{
	INT32 i;
	PIMAGE_SECTION_HEADER sect_hdr;

	if( size == 0 /*&& NULL == virt_addr*/ )
	{
		*finded_sect = NULL;
		return NULL;
	}

	sect_hdr = sect_hdrs;

	for( i = 0; i < sect_num; i ++ )
	{
		if( virt_addr >= sect_hdr->VirtualAddress &&
			virt_addr + size <= sect_hdr->VirtualAddress + sect_hdr->SizeOfRawData )
		{
			PBYTE data_out;
			*finded_sect = sect_hdr;
			
			return data + sect_hdr->PointerToRawData +  ( virt_addr - sect_hdr->VirtualAddress );
		}

		sect_hdr ++;
	}

	*finded_sect = NULL;
	return ( PBYTE )NULL;
}

PBYTE find_virt_addr_ptr( PIMAGE_DATA_DIRECTORY dir, PIMAGE_SECTION_HEADER sect_hdrs, DWORD sect_num, PBYTE data, PIMAGE_SECTION_HEADER *finded_sect )
{
	return find_virt_addr_ptr2( dir->VirtualAddress, dir->Size, sect_hdrs, sect_num, data, finded_sect );
}

INT32 read_copyright( PIMAGE_DATA_DIRECTORY copyright, PIMAGE_SECTION_HEADER sects, DWORD sect_num, PBYTE data )
{
	PBYTE copyright_buf;
	PBYTE copyright_ptr;
	PIMAGE_DATA_DIRECTORY finded_sect;

	copyright_ptr = find_virt_addr_ptr( copyright, sects, sect_num, data, &finded_sect );
	if( NULL == copyright )
	{
		return -1;
	}

	copyright_buf = ( PBYTE )malloc( copyright->Size + 1 );
	memcpy( copyright_buf, copyright_ptr, copyright->Size );
	copyright_buf[ copyright->Size ] = '\0';
	return 0;
}

INT32 read_export_syms( PIMAGE_DATA_DIRECTORY export_syms, PIMAGE_SECTION_HEADER sects, DWORD sect_num, PBYTE data )
{
	INT32 i;
	PDWORD function_rvas;
	PDWORD func_name_rvas;
	PDWORD func_name_ord_rvas;
	DWORD function_rva;
	PCHAR func_name;
	DWORD func_name_ord;
	PIMAGE_EXPORT_DIRECTORY export_table;
	PIMAGE_SECTION_HEADER finded_sect;

	export_table = find_virt_addr_ptr( export_syms, sects, sect_num, data, &finded_sect );
	if( NULL == export_table )
	{
		return -1;
	}

	export_table->Characteristics;
	export_table->TimeDateStamp;
	export_table->MajorVersion;
	export_table->MinorVersion;
	export_table->Name;
	export_table->Base;

	function_rvas = find_virt_addr_ptr2( export_table->AddressOfFunctions, sizeof( DWORD ) * export_table->NumberOfFunctions, sects, sect_num, data, &finded_sect );
	if( NULL == function_rvas )
	{
		return -1;
	}

	for( i = 0; i < export_table->NumberOfFunctions; i ++ )
	{
		function_rva = find_virt_addr_ptr2( function_rvas[ i ], sizeof( DWORD ), sects, sect_num, data, &finded_sect );
		if( NULL == function_rva )
		{
			;
		}
		
	}

	func_name_ord_rvas = find_virt_addr_ptr2( export_table->AddressOfNameOrdinals, sizeof( DWORD ) * export_table->NumberOfFunctions, sects, sect_num, data, &finded_sect );
	func_name_rvas = find_virt_addr_ptr2( export_table->AddressOfNames, sizeof( DWORD ) * export_table->NumberOfFunctions, sects, sect_num, data, &finded_sect );
	if( NULL == func_name_rvas || NULL == func_name_ord_rvas )
	{
		return -1;
	}

	for( i = 0; i < export_table->NumberOfNames; i ++ )
	{
		func_name = find_virt_addr_ptr2( func_name_rvas[ i ], sizeof( DWORD ), sects, sect_num, data, &finded_sect );
		func_name_ord = find_virt_addr_ptr2( func_name_ord_rvas[ i ], sizeof( DWORD ), sects, sect_num, data, &finded_sect );
	}
	
	export_table->AddressOfNameOrdinals;
}

INT32 read_import_func_info( DWORD import_name_rva, PIMAGE_SECTION_HEADER sects, DWORD sect_num, PBYTE data )
{
	INT32 ret;
	PIMAGE_THUNK_DATA thunk;
	PIMAGE_IMPORT_BY_NAME import_info;
	PIMAGE_SECTION_HEADER finded_sect;

	thunk = find_virt_addr_ptr2( import_name_rva, sizeof( IMAGE_IMPORT_BY_NAME ), sects, sect_num, data, &finded_sect );

	if( NULL == thunk )
	{
		return -1;
	}

	for( ; ; )
	{
		__asm
		{
			mov ecx, 0x04;
			mov edi, thunk;
			xor eax, eax;
			repz scasb;
			mov dword ptr [ret], ecx;
		}

		if( 0 == ret )
		{
			return 0;
		}

		import_info = find_virt_addr_ptr2( thunk->u1.AddressOfData, sizeof( IMAGE_THUNK_DATA ), sects, sect_num, data, &finded_sect );
		import_info->Hint;
		import_info->Name;
		thunk ++;
	}

	return 0;
}

INT32 read_import_syms( PIMAGE_DATA_DIRECTORY import_syms, PIMAGE_SECTION_HEADER sects, DWORD sect_num, PBYTE data )
{
	INT32 ret;
	PIMAGE_IMPORT_DESCRIPTOR import_desc;
	PIMAGE_SECTION_HEADER finded_sect;

	import_desc = find_virt_addr_ptr( import_syms, sects, sect_num, data, &finded_sect );
	if( NULL == import_desc )
	{
		return -1;
	}

	for( ; ; )
	{
		__asm
		{
			mov ecx, 0x14;
			mov edi, import_desc;
			xor eax, eax;
			repz scasb;
			mov dword ptr [ret], ecx;
		}

		if( ret == 0 )
		{
			return 0;
		}

		import_desc->OriginalFirstThunk;
		import_desc->TimeDateStamp;
		import_desc->ForwarderChain;
		import_desc->Name;
		import_desc->FirstThunk;
		import_desc->Characteristics;

		read_import_func_info( import_desc->OriginalFirstThunk, sects, sect_num, data );

		import_desc ++;
	}

	return -1;
}

INT32 read_resource_data( PIMAGE_RESOURCE_DATA_ENTRY res_data, PBYTE sect_data, PIMAGE_RESOURCE_DATA_ENTRY res_data_out )
{
	ASSERT( NULL != res_data );
	ASSERT( NULL != sect_data );
	ASSERT( NULL != res_data_out );

	res_data_out->CodePage = res_data->CodePage;
	res_data_out->Size = res_data->Size;
	res_data_out->OffsetToData = ( PBYTE )malloc( res_data->Size );
	if( NULL == res_data_out->OffsetToData )
	{
		return -1;
	}

	memcpy( res_data_out->OffsetToData, res_data->OffsetToData + sect_data, res_data->Size );
	return 0;
}

#define MAX_RES_NAME_LEN 512
INT32 read_resource_info( PIMAGE_RESOURCE_DIRECTORY res_dir, PBYTE sect_data )
{
	INT32 i;
	INT32 ret;
	PIMAGE_RESOURCE_DATA_ENTRY res_data;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY res_entry;
	PIMAGE_RESOURCE_DIR_STRING_U res_name;
	WCHAR res_name_buf[ MAX_RES_NAME_LEN ];

	res_dir->Characteristics;
	res_dir->TimeDateStamp;
	res_dir->MajorVersion;
	res_dir->MinorVersion;
	res_dir->NumberOfNamedEntries;
	res_dir->NumberOfIdEntries;

	res_entry = ( res_dir + 1 );
	for( i = 0; i < res_dir->NumberOfNamedEntries + res_dir->NumberOfIdEntries; i ++ )
	{
		if( res_entry->NameIsString )
		{
			res_name = sect_data + res_entry->Name;
			memcpy( res_name_buf, res_name->NameString, res_name->Length * sizeof( WCHAR ) );
			res_name_buf[ res_name->Length ] = L'\0';
			ret = WideCharToMultiByte( 0, 0, res_name_buf, 0, res_name_buf, MAX_RES_NAME_LEN * 2, NULL, NULL );
		}
		else
		{
			res_entry->Id;
		}

		if( res_entry->DataIsDirectory )
		{
			read_resource_info( res_entry->OffsetToDirectory + sect_data, sect_data );
		}
		else
		{
			res_data = sect_data + res_entry->OffsetToData;
			res_data->OffsetToData;
			res_data->Size;
			res_data->CodePage;
			res_data->Reserved;
		}

		res_entry ++;
	}
	return 0;
}

INT32 read_resource_table( PIMAGE_DATA_DIRECTORY resource_table, PIMAGE_SECTION_HEADER sects, DWORD sect_num, PBYTE data )
{
	INT32 ret;
	INT32 i;
	PIMAGE_RESOURCE_DIRECTORY res_dir;
	PIMAGE_SECTION_HEADER finded_sect;

	res_dir = find_virt_addr_ptr( resource_table, sects, sect_num, data, &finded_sect );

	if( NULL == res_dir )
	{
		return -1;
	}

	read_resource_info( res_dir, data + finded_sect->PointerToRawData );
}

INT32 read_directories( PIMAGE_DATA_DIRECTORY dirs, DWORD dir_num, PIMAGE_SECTION_HEADER sects, DWORD sect_num, PBYTE data )
{
	PIMAGE_DATA_DIRECTORY data_dirs;

	data_dirs = dirs;

	read_export_syms( &data_dirs[ IMAGE_DIRECTORY_ENTRY_EXPORT ], sects, sect_num, data );
	read_import_syms( &data_dirs[ IMAGE_DIRECTORY_ENTRY_IMPORT ], sects, sect_num, data );
	read_resource_table( &data_dirs[ IMAGE_DIRECTORY_ENTRY_RESOURCE ], sects, sect_num, data );
	data_dirs[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ];
	data_dirs[ IMAGE_DIRECTORY_ENTRY_SECURITY ];
	data_dirs[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
	data_dirs[ IMAGE_DIRECTORY_ENTRY_DEBUG ];
	data_dirs[ IMAGE_DIRECTORY_ENTRY_GLOBALPTR ];
	data_dirs[ IMAGE_DIRECTORY_ENTRY_TLS ];
	data_dirs[ IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG ];
	data_dirs[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ];
	data_dirs[ IMAGE_DIRECTORY_ENTRY_IAT ];

	return 0;
}

INT32 read_sections( PIMAGE_SECTION_HEADER *sects, DWORD sect_num )
{
	INT32 i;
	PIMAGE_SECTION_HEADER sect_hdr;

	sect_hdr = sects;

	for( i = 0; i < sect_num; i ++ )
	{
		sect_hdr->Name;
		sect_hdr->Misc.VirtualSize;
		sect_hdr->VirtualAddress;
		sect_hdr->SizeOfRawData;
		sect_hdr->PointerToRawData;
		sect_hdr->PointerToRelocations;
		sect_hdr->PointerToLinenumbers;
		sect_hdr->NumberOfRelocations;
		sect_hdr->NumberOfLinenumbers;

		if( sect_hdr->Characteristics & IMAGE_SCN_TYPE_NO_PAD )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_CNT_CODE )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_LNK_OTHER )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_LNK_INFO )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_LNK_REMOVE )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_LNK_COMDAT )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_NO_DEFER_SPEC_EXC )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_GPREL )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_MEM_FARDATA )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_MEM_PURGEABLE )
		{
		}	
		if( sect_hdr->Characteristics & IMAGE_SCN_MEM_16BIT )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_MEM_LOCKED )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_MEM_PRELOAD )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_ALIGN_1BYTES )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_ALIGN_2BYTES )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_ALIGN_4BYTES )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_ALIGN_8BYTES )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_ALIGN_16BYTES )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_ALIGN_32BYTES )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_ALIGN_64BYTES )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_ALIGN_128BYTES )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_ALIGN_256BYTES )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_ALIGN_512BYTES )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_ALIGN_1024BYTES )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_ALIGN_2048BYTES )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_ALIGN_4096BYTES )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_ALIGN_8192BYTES )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_MEM_DISCARDABLE )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_MEM_NOT_CACHED )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_MEM_NOT_PAGED )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_MEM_SHARED )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_MEM_READ )
		{
		}
		if( sect_hdr->Characteristics & IMAGE_SCN_MEM_WRITE )
		{
		}

		sect_hdr ++;
	}
	return 0;
}

INT32 analyze_pe_file( HANDLE hFile )
{
	INT32 i;
	BOOL ret;
	PBYTE pe_hdr;
	PIMAGE_DOS_HEADER dos_hdr;
	PIMAGE_FILE_HEADER file_hdr;
	PIMAGE_OPTIONAL_HEADER option_hdr;
	PIMAGE_DATA_DIRECTORY data_dirs;
	PIMAGE_SECTION_HEADER sect_hdr;
	DWORD readed;
	DWORD offset;
	DWORD dir_num;
	PBYTE dos_stub;
	DWORD file_len;

	ASSERT( INVALID_HANDLE_VALUE != hFile );

	offset = 0;
	file_len = SetFilePointer( hFile, 0, NULL, SEEK_END );
	SetFilePointer( hFile, 0, NULL, SEEK_SET );

	pe_hdr = ( PBYTE )malloc( file_len );
	if( NULL == pe_hdr )
	{
		ret = -1;
		goto error;
	}

	ret = ReadFile( hFile, pe_hdr, file_len, &readed, NULL );
	if( FALSE == ret )
	{
		ret = -1;
		goto error;
	}

	dos_hdr = pe_hdr + offset;
	if( IMAGE_DOS_SIGNATURE != dos_hdr->e_magic )
	{
		ret = -1;
		goto error;
	}

	offset += sizeof( IMAGE_DOS_HEADER );
	dos_stub = pe_hdr + offset;

	offset += dos_hdr->e_lfanew - sizeof( IMAGE_DOS_HEADER );
	if( IMAGE_NT_SIGNATURE != *( DWORD* )( pe_hdr + offset ) )
	{
		ret = -1;
		goto error;
	}

	offset += sizeof( DWORD );
	file_hdr = pe_hdr + offset;

	switch( file_hdr->Machine )
	{
	case IMAGE_FILE_MACHINE_I386:
		break;
	case 0x014d:
		break;
	case 0x014e:
		break;
	case 0x0160:
		break;
	case IMAGE_FILE_MACHINE_R3000:
		break;
	case IMAGE_FILE_MACHINE_R4000:
		break;
	case IMAGE_FILE_MACHINE_R10000:
		break;
	case IMAGE_FILE_MACHINE_ALPHA:
		break;
	case IMAGE_FILE_MACHINE_POWERPC:
		break;
	default:
		ret = -1;
		goto error;
		break;
	}

	if( file_hdr->SizeOfOptionalHeader != sizeof( IMAGE_OPTIONAL_HEADER ) )
	{
		ret = -1;
		goto error;
	}

	if( file_hdr->Characteristics & IMAGE_FILE_RELOCS_STRIPPED )
	{

	}

	if( file_hdr->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE )
	{

	}

	if( file_hdr->Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED )
	{

	}

	if( file_hdr->Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED )
	{

	}

	if( file_hdr->Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM )
	{

	}

	if( file_hdr->Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE )
	{

	}

	if( file_hdr->Characteristics & IMAGE_FILE_BYTES_REVERSED_LO )
	{

	}

	if( file_hdr->Characteristics & IMAGE_FILE_32BIT_MACHINE )
	{

	}


	if( file_hdr->Characteristics & IMAGE_FILE_DEBUG_STRIPPED )
	{

	}

	if( file_hdr->Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP )
	{

	}

	if( file_hdr->Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP )
	{

	}

	if( file_hdr->Characteristics & IMAGE_FILE_SYSTEM )
	{

	}

	if( file_hdr->Characteristics & IMAGE_FILE_DLL )
	{

	}

	if( file_hdr->Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY )
	{

	}

	if( file_hdr->Characteristics & IMAGE_FILE_BYTES_REVERSED_HI )
	{

	}

	offset += sizeof( IMAGE_FILE_HEADER );
	option_hdr = pe_hdr + offset;

	if( option_hdr->Magic != 0x010b )
	{
		ret = -1;
		goto error;
	}

	option_hdr->AddressOfEntryPoint;
	option_hdr->ImageBase;
	option_hdr->SectionAlignment;
	option_hdr->FileAlignment;
	option_hdr->MinorSubsystemVersion;
	option_hdr->SizeOfImage;
	option_hdr->SizeOfHeaders;
	option_hdr->CheckSum; //CheckSumMappedFile()

	switch( option_hdr->Subsystem )
	{
	case IMAGE_SUBSYSTEM_NATIVE:
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		break;
	case IMAGE_SUBSYSTEM_OS2_CUI:
		break;
	case IMAGE_SUBSYSTEM_POSIX_CUI:
		break;
	default:
		ret = -1;
		goto error;
		break;
	}

	option_hdr->SizeOfStackReserve;
	option_hdr->SizeOfStackCommit;
	option_hdr->SizeOfHeapReserve;
	option_hdr->SizeOfHeapCommit;
	dir_num = option_hdr->NumberOfRvaAndSizes; //IMAGE_NUMBEROF_DIRECTORY_ENTRIES

	if( dir_num > IMAGE_NUMBEROF_DIRECTORY_ENTRIES )
	{
		dir_num = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	}

	data_dirs = &option_hdr->DataDirectory;

	offset += sizeof( IMAGE_OPTIONAL_HEADER );

	sect_hdr = ( PIMAGE_SECTION_HEADER )( pe_hdr + offset );

	read_directories( data_dirs,dir_num, sect_hdr, file_hdr->NumberOfSections, pe_hdr );
	read_sections( sect_hdr, file_hdr->NumberOfSections, pe_hdr );

error:
	if( NULL != pe_hdr )
	{
		free( pe_hdr );
	}

	return ret;
}