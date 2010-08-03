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

coff_analyzer *global_analyzer = NULL;

void set_sym_process_func( coff_analyzer *analyzer )
{
	global_analyzer = analyzer;
}

int start_analyze_file( CHAR *filename, coff_analyzer *analyzer )
{
	int ret;
	byte *data;
	dword data_len;

	ret = read_all_file_data( filename, &data, &data_len );
	if( 0 != ret )
	{
		return -1;
	}

	ret = check_lib_file_header( data, data_len );
	if( 0 != ret )
	{
		ret = analyze_pe_file( data, data_len, analyzer );
	}
	else
	{
		ret = read_lib_func_info( data, data_len, analyzer  );
	}

	return ret;
}
