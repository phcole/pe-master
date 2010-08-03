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
