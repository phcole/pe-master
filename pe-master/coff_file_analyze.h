#ifndef __COFF_FILE_ANALYZE_H__
#define __COFF_FILE_ANALYZE_H__

#pragma pack( push )
#pragma pack( 1 )

typedef struct __coff_file_hdr{
  unsigned short magic;  // 魔法数字
  unsigned short sect_num;  // 段落（Section）数
  unsigned long  time;  // 时间戳
  unsigned long  syms_offset;  // 符号表偏移
  unsigned long  syms_num;  // 符号数
  unsigned short opt_hdr_size;  // 可选头长度
  unsigned short flags;  // 文件标记
} coff_file_hdr;

typedef struct __coff_opt_hdr28{
  unsigned short magic;  // 魔法数字
  unsigned short version;  // 版本标识
  unsigned long  text_size;  // 正文（text）段大小
  unsigned long  init_data_size;  // 已初始化数据段大小
  unsigned long  uninit_data_size;  // 未初始化数据段大小
  unsigned long  entry;  // 入口点
  unsigned long  text_base;  // 正文段基址
  unsigned long  data_base;  // 数据段基址（在PE32中才有）
} coff_opt_hdr28;


typedef struct __coff_sect_hdr{
  char           name[8];  // 段名
  unsigned long  virt_size;  // 虚拟大小
  unsigned long  virt_addr;  // 虚拟地址
  unsigned long  size;  // 段长度
  unsigned long  sect_offset;  // 段数据偏移
  unsigned long  sect_rel_offset;  // 段重定位表偏移
  unsigned long  ln_table_offset;  // 行号表偏移
  unsigned short rel_offset_num;  // 重定位表长度
  unsigned short ln_num;  // 行号表长度
  unsigned long  flags;  // 段标识
  //unsigned long reserved;
} coff_sect_hdr;

typedef struct __coff_reloc{
  unsigned long  ulAddr;  // 定位偏移
  unsigned long  ulSymbol;  // 符号
  unsigned short usType;  // 定位类型
} coff_reloc;

typedef struct {
    unsigned long addr_symbol;  // 代码地址或符号索引
    unsigned short ln_no;  // 行号
} coff_ln_info;

typedef struct __coff_sym_ent{
  union {
    char name[8];            // 符号名称
    struct {
      unsigned long zero;   // 字符串表标识
      unsigned long offset; // 字符串偏移
    } id;
  } sym_id;
  unsigned long value;     // 符号值
  short section;            // 符号所在段
  unsigned short type;     // 符号类型
  unsigned char __class;     // 符号存储类型
  unsigned char aux_num;    // 符号附加记录数
} coff_sym_ent;

typedef struct __coff_str_table
{
	dword size;
	char strings[1];
} coff_str_table;
#pragma pack( pop )

#endif //__COFF_FILE_ANALYZE_H__