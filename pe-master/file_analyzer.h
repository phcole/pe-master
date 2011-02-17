#ifndef __FILE_ANALYZER_H__
#define __FILE_ANALYZER_H__

#define ERR_FILE_NOT_EXIST 0x0001000a

#ifdef __cplusplus
extern "C" {
#endif

int32 check_file_type( byte *data, dword data_len );
int init_analyzing( CHAR *filename, file_analyzer *analyzer );
struct_infos *find_struct_info( struct_infos *info );
struct_infos *find_struct_info_by_id( dword type, dword index );
int32 callback compare_struct_info( void *element1, void *element2 ); 
int32 callback check_max_index_ele( void *element1, void *element2 ); 

#ifdef __cplusplus
}
#endif
#endif //__FILE_ANALYZER_H__