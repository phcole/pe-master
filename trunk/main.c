/*
 * Copyright 2010 JiJie Shi
 *
 * This file is part of BalanceParallel.
 *
 * BalanceParallel is free software: you can redistribute it and/or modify
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
 * along with BalanceParallel.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include "common.h"
#include "pe_analyze.h"

#define USAGE_TIP "usage:\n	pereader.exe filename the filename argument is the name of pe file to analyze\n"

VOID help()
{
	printf( USAGE_TIP );
}

INT32 main( INT32 argc, CHAR *argv[] )
{
	HANDLE hFile;

	DWORD cs_cont;
	__asm
	{
		xor eax, eax;
		push cs;
		pop eax;
		;mov dword ptr [cs_cont], eip;
		
	}

	if( argc < 2 )
	{
		help();
		return -1;
	}

	hFile = CreateFile( argv[ 1 ], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
	if( INVALID_HANDLE_VALUE == hFile )
	{
		return -1;
	}

	analyze_pe_file( hFile );
	return 0;
}