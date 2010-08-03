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

#ifndef __COFF_FILE_ANALYZE_H__
#define __COFF_FILE_ANALYZE_H__

#pragma pack( push )
#pragma pack( 1 )

typedef struct __coff_file_hdr{
  unsigned short magic;  
  unsigned short sect_num;
  unsigned long  time;
  unsigned long  syms_offset;
  unsigned long  syms_num;
  unsigned short opt_hdr_size;
  unsigned short flags;
} coff_file_hdr;

typedef struct __coff_opt_hdr28{
  unsigned short magic;  
  unsigned short version;
  unsigned long  text_size;
  unsigned long  init_data_size;
  unsigned long  uninit_data_size;
  unsigned long  entry;
  unsigned long  text_base;
  unsigned long  data_base;
} coff_opt_hdr28;


typedef struct __coff_sect_hdr{
  char           name[8];
  unsigned long  virt_size;
  unsigned long  virt_addr;
  unsigned long  size;
  unsigned long  sect_offset;
  unsigned long  sect_rel_offset;
  unsigned long  ln_table_offset;
  unsigned short rel_offset_num;
  unsigned short ln_num;
  unsigned long  flags;
  //unsigned long reserved;
} coff_sect_hdr;

typedef struct __coff_reloc{
  unsigned long  ulAddr;
  unsigned long  ulSymbol;
  unsigned short usType;
} coff_reloc;

typedef struct {
    unsigned long addr_symbol;
    unsigned short ln_no;
} coff_ln_info;

typedef struct __coff_sym_ent{
  union {
    char name[8];
    struct {
      unsigned long zero;
      unsigned long offset;
    } id;
  } sym_id;
  unsigned long value;
  short section;
  unsigned short type;
  unsigned char __class;
  unsigned char aux_num;
} coff_sym_ent;

typedef struct __coff_str_table
{
	dword size;
	char strings[1];
} coff_str_table;
#pragma pack( pop )

#endif //__COFF_FILE_ANALYZE_H__