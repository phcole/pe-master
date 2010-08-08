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

void littelendian2bigendian( void * p, size_t size )
{
	int i;
	char * buf = ( char* )p;
	char temp;
	for ( i=0;i < size / 2; i++ ) {
		temp = buf[ i ];
		buf[ i ] = buf[ size - i - 1 ];
		buf[ size - i - 1 ] = temp;
	}
} 

int mem_submem( byte* target_cont, int target_cont_len, byte* src_mem, int src_mem_len)
{
	int __target_len;
	byte* __src_mem;
	int end_index;
	byte is_same;
	int i, j;

	if( src_mem_len < target_cont_len )
		return -1;

	__target_len = target_cont_len;
	__src_mem = src_mem;

	end_index = src_mem_len - target_cont_len + 1;

	for(i = 0; i < end_index; i ++)
	{
		is_same = TRUE;
		for( j = 0; j < target_cont_len; j++ )
		{
			if(target_cont[j] != __src_mem[i + j])
			{
				is_same = FALSE;
				break;
			}
			else
			{
				int j = 0;
			}
		}

		if( is_same )
			return i;
	}
	return -1;
}

int write_to_new_file( char *file_path, char *file_name, byte *data, dword data_len )
{
	int ret = 0;
	HANDLE hfile;
	dword writed;
	char new_file_name[ MAX_PATH ];

	ASSERT( NULL != file_name );
	ASSERT( NULL != data );
	ASSERT( NULL != data_len );

	strcpy( new_file_name, file_path );
	strcat( new_file_name, "\\" );
	strcat( new_file_name, file_name );

	hfile = CreateFile( new_file_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, 0, NULL );
	if( INVALID_HANDLE_VALUE == hfile )
	{
		return -1;
	}

	ret = WriteFile( hfile, data, data_len, &writed, NULL );
	if( FALSE == ret || writed != data_len )
	{
		ret = -1;
		goto __error;
	}

__error:
	if( INVALID_HANDLE_VALUE != hfile )
	{
		CloseHandle( hfile );
	}

	return ret;
}

int read_all_file_data( char *file_name, byte **data, dword *data_len )
{
	int ret = 0;
	HANDLE hfile;
	dword file_len = 0;
	byte *__data = NULL;
	dword readed;

	ASSERT( NULL != data );
	ASSERT( NULL != data_len );

	hfile = CreateFile( file_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
	if( INVALID_HANDLE_VALUE == hfile )
	{
		return -1;
	}

	file_len = SetFilePointer( hfile, 0, NULL, SEEK_END );
	SetFilePointer( hfile, 0, NULL, SEEK_SET );

	__data = ( PBYTE )malloc( file_len );
	if( NULL == __data )
	{
		ret = -1;
		goto __return;
	}

	ret = ReadFile( hfile, __data, file_len, &readed, NULL );
	if( FALSE == ret || readed != file_len )
	{
		ret = -1;
		goto __error;
	}

	ret = 0;
	goto __return;

__error:
	if( NULL != __data )
	{
		free( __data );
		__data = NULL;
	}

	file_len = 0;

__return:
	if( INVALID_HANDLE_VALUE != hfile )
	{
		CloseHandle( hfile );
	}

	*data = __data;
	*data_len = file_len;
	return ret;
}

int release_file_data( byte *data )
{
	free( data );
}

void dump_mem( void *mem, int size )
{
	unsigned char str[20];
	unsigned char *m = mem;
	int i,j;

	for (j = 0; j < size / 8; j++)
	{
		memset( str, 0, sizeof( str ) );
		for (i = 0; i < 8; i++) 
		{
			if (m[i] > ' ' && m[i] <= '~')
			{
				str[i] = m[i];
			}
			else
			{
				str[i] = '.';
			}
		}

		sprintf( "0x%08p  %02x %02x %02x %02x %02x %02x %02x %02x  %s\n",
			m, m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], str);

		m+=8;
	}
}