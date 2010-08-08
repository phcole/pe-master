#ifndef __FILE_ANALYZER_H__
#define __FILE_ANALYZER_H__

#define ERR_FILE_NOT_EXIST 0x0001000a

#ifdef __cplusplus
extern "C" {
#endif

int32 check_file_type( byte *data, dword data_len );
int start_analyze_file( CHAR *filename, file_analyzer *analyzer );

#ifdef __cplusplus
}
#endif
#endif //__FILE_ANALYZER_H__