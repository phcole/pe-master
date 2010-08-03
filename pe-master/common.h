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
#ifndef __COMMON_H__
#define __COMMON_H__

#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <malloc.h>

#ifndef ASSERT
#ifdef _DEBUG
#include <assert.h>
#define ASSERT( x ) assert( x )
#else
#define ASSERT( x )
#endif
#endif

#define CONST_STR_LEN( string ) ( int )( sizeof( string ) - sizeof( char ) )

typedef unsigned long dword;
typedef unsigned char byte;

int read_all_file_data( char *file_name, byte **data, dword *data_len );

#endif //__COMMON_H__
