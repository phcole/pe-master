#ifndef __COMMON_ANALYZE_H__
#define __COMMON_ANALYZE_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct __code_infos
{
	char *func_name;
	byte *func_code;
	dword func_code_len;

} code_infos;

typedef struct __sym_infos
{
	char *sym_name;
	byte *sym_data;
	dword sym_data_len;
} sym_infos;

typedef int ( *sym_info_proc )( sym_infos *sym_info, void *context );
typedef int ( *code_info_proc )( code_infos *sym_info, void *context );

typedef struct __coff_analyzer
{
	sym_info_proc syms_analyze;
	sym_info_proc strs_analyze;
	code_info_proc code_analyze;
	void *context;

} coff_analyzer;

int start_analyze_file( CHAR *filename, coff_analyzer *analyzer );
void set_sym_process_func( coff_analyzer *analyzer );

#ifdef __cplusplus
}
#endif

#endif //__COMMON_ANALYZE_H__