#ifndef __PE_MAKE_H__
#define __PE_MAKE_H__

#define FILE_ALIGN_MODE 0x01
#define MEM_ALIGN_MODE 0x02
#define CODE_ENTRY_POINT 0x00000001

#ifdef __cplusplus
extern "C" {
#endif

dword get_aligned_val( byte* pe_file_data, dword org_val, dword mode );
int32 create_pe_file( char *file_name, dword *pe_handle );
int32 add_codes( dword pe_handle, byte *codes, dword code_len, dword flags );
int32 init_pe_make();
int32 uninit_pe_make();

#ifdef __cplusplus
}
#endif

#endif //__PE_MAKE_H__