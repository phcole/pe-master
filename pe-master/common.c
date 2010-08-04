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

int mem_submem(byte* pSubMem, int nSubMemLen, byte* pMem, int nMemLen)
{
	int nSubLen;
	byte* pSrcStr;
	int nEndIndex;
	byte bIsSame;
	int i, j;

	if(nMemLen < nSubMemLen)
		return -1;

	nSubLen = nSubMemLen;
	pSrcStr = pMem;

	nEndIndex = nMemLen - nSubMemLen + 1;
	bIsSame;

	for(i = 0; i < nEndIndex; i ++)
	{
		bIsSame = TRUE;
		for( j = 0; j < nSubMemLen; j++)
		{
			if(pSubMem[j] != pSrcStr[i + j])
			{
				bIsSame = FALSE;
				break;
			}
			else
			{
				int j = 0;
			}
		}

		if(bIsSame)
			return i;
	}
	return -1;
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