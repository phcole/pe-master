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

// pe-analyzerDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "resource.h"
#include "pe-analyzerDlg.h"
#include ".\pe-analyzerdlg.h"

#pragma comment( lib, "pe-master.lib" )

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define MAX_DESC_INFO_LEN 4096
#define MAX_FILTER_LEN 1024
CHAR g_szFilter[ MAX_FILTER_LEN ] = { 0 };

#define FIND_SUB_TREE_TRAVERSE 0x01
#define LIB_FILE_TITLE "LIB FILE"
#define LIB_SECTION1_TITLE "SECTION1"
#define LIB_SECTION2_TITLE "SECTION2"
#define LIB_LONGNAME_SECTION_TITLE "LONG NAME SECTION"
#define LIB_OBJ_FILE_SECTION_TITLE "OBJ FILE SECTION "

#define COFF_FILE_TITLE "COFF FILE"

typedef struct __sym_org_data
{
	byte *sym_data;
	dword sym_data_len;
} sym_org_data;

typedef struct __analyze_data
{
	byte *data;
	analyze_context *context;
} analyze_data;

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CpeanalyzerDlg 对话框


CpeanalyzerDlg *g_pDlg;
CpeanalyzerDlg::CpeanalyzerDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CpeanalyzerDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CpeanalyzerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CpeanalyzerDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDOK, OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, OnBnClickedCancel)
	ON_BN_CLICKED(IDC_BUTTON_SEL_FILE, OnBnClickedButtonSelFile)
	ON_BN_CLICKED(IDC_STOP_ANALYZE, OnBnClickedStopAnalyze)
	ON_NOTIFY(TVN_SELCHANGED, IDC_TREE_MAIN, OnTvnSelchangedTreeMain)
	ON_NOTIFY(TVN_SELCHANGED, IDC_TREE_DETAIL, OnTvnSelchangedTreeDetail)
	ON_NOTIFY(NM_RCLICK, IDC_TREE_MAIN, OnRClientTreeMain )
	ON_MESSAGE( WM_DO_UI_WORK, OnDoUIWork )
	ON_WM_MEASUREITEM()
	ON_WM_INITMENUPOPUP()
END_MESSAGE_MAP()


// CpeanalyzerDlg 消息处理程序

dword create_context_menu( HWND parent )
{
	int32 ret;
	dword seled_menu;
	HMENU menu_popup;
	POINT cur_pt;
 
	ASSERT( NULL != parent );
	GetCursorPos( &cur_pt );

	menu_popup = CreatePopupMenu(); 
	ret = AppendMenu( menu_popup, MF_STRING, 
		(UINT)MENU_ITEM_ID_DUMP_OBJ, "&dump this .obj file" );

	seled_menu = TrackPopupMenuEx( menu_popup, 
		TPM_LEFTALIGN | TPM_LEFTBUTTON | TPM_RETURNCMD, 
		cur_pt.x, cur_pt.y, parent, NULL); 

	//dword err = GetLastError();
	DestroyMenu( menu_popup ); 

    return seled_menu;
}

int32 init_wnd_feature( CpeanalyzerDlg *dlg )
{
	HWND tree_main;
	HWND tree_detail;

	ASSERT( NULL != dlg );

	tree_main = ( HWND )dlg->GetDlgItem( IDC_TREE_MAIN );
	tree_detail = ( HWND )dlg->GetDlgItem( IDC_TREE_DETAIL );
	
	::SendMessage( tree_main, TVM_SETBKCOLOR, 0, 0x00e1f0ff );
	::SendMessage( tree_main, TVM_SETTEXTCOLOR, 0, 0x00ffffe0 );
	::SendMessage( tree_main, TVM_SETLINECOLOR, 0, 0x00ffffe0 );
	::SendMessage( tree_main, TVM_SETINSERTMARKCOLOR, 0, 0x00ffffe0 );

	return 0;
}

HTREEITEM insert_text_in_tree( HWND tree, HTREEITEM tree_item, const char *str_insert, byte *data )
{
	TV_INSERTSTRUCT tvis;
	HTREEITEM sub_tree;

	ASSERT( NULL != tree );
	ASSERT( NULL != str_insert );

	if( TVI_ROOT == tree_item )
	{
		tvis.hParent = NULL;
		tvis.hInsertAfter = tree_item;
	}
	else
	{
		tvis.hParent = tree_item;
		tvis.hInsertAfter = NULL;
	}

	tvis.item.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM;
	tvis.item.pszText = ( char* )str_insert;
	tvis.item.iImage = -1;
	tvis.item.iSelectedImage = -1;
	tvis.item.lParam = ( DWORD )data;

	sub_tree = ( HTREEITEM )SendMessage( tree, TVM_INSERTITEM, 0, ( LPARAM )&tvis );
	return sub_tree;
}

int32 add_lib_section_desc( lib_section_hdr *section1, HTREEITEM tree_item, analyze_context *context )
{
	char desc[ MAX_DESC_INFO_LEN ];

	HWND tree_main;
	HTREEITEM tree_ret;

	tree_main = context->tree_main;

	sprintf( desc, "0x%0.8x Section group id: %s", ( ( byte* )&section1->group_id[ 0 ] - context->analyzer.all_file_data ), section1->group_id );
	tree_ret = insert_text_in_tree( tree_main, tree_item, desc, NULL );

	sprintf( desc, "0x%0.8x Section user id: %s", ( ( byte* )&section1->user_id[ 0 ] - context->analyzer.all_file_data ), section1->user_id );
	tree_ret = insert_text_in_tree( tree_main, tree_item, desc, NULL );

	sprintf( desc, "0x%0.8x Section mode: %s", ( ( byte* )&section1->mode[ 0 ] - context->analyzer.all_file_data ), section1->mode );
	tree_ret = insert_text_in_tree( tree_main, tree_item, desc, NULL );

	sprintf( desc, "0x%0.8x Section name: %s", ( ( byte* )&section1->name[ 0 ] - context->analyzer.all_file_data ), section1->name );
	tree_ret = insert_text_in_tree( tree_main, tree_item, desc, NULL );

	sprintf( desc, "0x%0.8x Section size: %s", ( ( byte* )&section1->size[ 0 ] - context->analyzer.all_file_data ), section1->size );
	tree_ret = insert_text_in_tree( tree_main, tree_item, desc, NULL );

	sprintf( desc, "0x%0.8x Section time: %s", ( ( byte* )&section1->time[ 0 ] - context->analyzer.all_file_data ), section1->time );
	tree_ret = insert_text_in_tree( tree_main, tree_item, desc, NULL );

	return 0;
}

HTREEITEM find_sub_tree_in_tree( HWND tree_main, HTREEITEM tree_item, char *find_str, dword flags )
{
#define MAX_TREE_ITEM_TITLE_LEN 512
	int ret;
	HTREEITEM sub_tree;
	HTREEITEM sib_tree;
	HTREEITEM ret_tree;
	TVITEM tv_item;
	char geted_str[ MAX_TREE_ITEM_TITLE_LEN ];

	ASSERT( NULL != find_str );
	ASSERT( NULL != tree_item );

	if( TVI_ROOT != tree_item )
	{
		memset( &tv_item, 0, sizeof( tv_item ) );
		tv_item.mask = TVIF_TEXT;
		tv_item.pszText = geted_str;
		tv_item.cchTextMax = MAX_TREE_ITEM_TITLE_LEN;
		tv_item.hItem = tree_item;
		ret = TreeView_GetItem( tree_main, &tv_item );
		if( FALSE == ret )
		{
			return NULL;
		}

		if( 0 == strcmp( tv_item.pszText, find_str ) )
		{
			return sub_tree;
		}
	}

	sub_tree = TreeView_GetChild( tree_main, tree_item );
	if( NULL == sub_tree )
	{
		return NULL;
	}

	memset( &tv_item, 0, sizeof( tv_item ) );
	tv_item.mask = TVIF_TEXT;
	tv_item.pszText = geted_str;
	tv_item.cchTextMax = MAX_TREE_ITEM_TITLE_LEN;
	tv_item.hItem = sub_tree;
	ret = TreeView_GetItem( tree_main, &tv_item );
	if( FALSE == ret )
	{
		return NULL;
	}

	if( 0 == strcmp( tv_item.pszText, find_str ) )
	{
		return sub_tree;
	}

	if( flags & FIND_SUB_TREE_TRAVERSE )
	{
		ret_tree = find_sub_tree_in_tree( tree_main, sub_tree, find_str, flags );
		if( NULL != ret_tree )
		{
			return ret_tree;
		}
	}

	sib_tree = TreeView_GetNextSibling( tree_main, sub_tree );
	if( NULL == sib_tree )
	{
		return NULL;
	}

	ret_tree = find_sub_tree_in_tree( tree_main, sib_tree, find_str, flags );
	if( NULL != ret_tree )
	{
		return ret_tree;
	}

	return NULL;
}

BOOL CpeanalyzerDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将\“关于...\”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);
	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	//GetDlgItem( IDC_EDIT_FILTER )->SetWindowText( "CString" );
	GetDlgItem( IDC_EDIT_PE_FILE_PATH )->SetWindowText( "C:\\WINDDK\\2600.1106\\lib\\wxp\\i386\\mfc42.lib" ); /*"E:\\Visual C++ 6.0 SP6简体中文版\\VC98\\LIB\\MSUILSTF.DLL" );*///"lib_sample.lib" );
	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	init_wnd_feature( this );

	g_pDlg = this;
	// TODO: 在此添加额外的初始化代码
	
	return TRUE;  // 除非设置了控件的焦点，否则返回 TRUE
}

void CpeanalyzerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CpeanalyzerDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标显示。
HCURSOR CpeanalyzerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

int sum( int num1, int num2 )
{
	return num1 + num2;
}

void dummy()
{
	int dummy = 0;
}

int ret_sample_func_code( byte **org_func_code, dword *func_code_len )
{
	int sum_val;
	dword func_addr_begin;
	dword func_addr_end;
	byte *func_code;

	sum_val = sum( 3, 6 );

	func_addr_begin = ( DWORD )( VOID* )sum;
	func_addr_end = ( DWORD )( VOID* )dummy;

	ASSERT( func_addr_end > func_addr_begin );

	func_code = ( BYTE* )malloc( func_addr_end - func_addr_begin );

	ASSERT( NULL != func_code );
	memcpy( func_code, ( void* )func_addr_begin, func_addr_end - func_addr_begin );

	if( *func_code == 0xe9 )
	{
		dword offset;
		offset = *( dword* )( func_code + sizeof( byte ) );
		offset += sizeof( dword ) + sizeof( byte );
		func_addr_begin += offset;
		func_addr_end += offset;
		func_addr_end = ( dword )memchr( ( void* )func_addr_begin, 0xcc, ( dword )( func_addr_end - func_addr_begin ) );
		if( NULL == func_addr_end )
		{
			return -1;
		}
	}

	memcpy( func_code, ( void* )func_addr_begin, func_addr_end - func_addr_begin );

	*org_func_code = func_code;
	*func_code_len = func_addr_end - func_addr_begin;

	return 0;
}

BOOL g_bStop;


int32 error_handle( error_infos *info )
{
	switch( info->err_code )
	{
	default:
		break;
	}

	return 0;
}

int32 analyze_pe_dos_header( PIMAGE_DOS_HEADER dos_hdr, analyze_context *context )
{

	return 0;
}

#define MAX_PE_OPTIONAL_DESC_LEN 4096
int32 analyze_pe_optional_hdr( PIMAGE_OPTIONAL_HEADER option_hdr, analyze_context *context )
{
	//HWND tree_main;
	//HWND tree_detail;
	//HWND sub_tree;
	//HWND ret;

	//char opt_hdr_desc[ MAX_PE_OPTIONAL_DESC_LEN ];
	//ASSERT( NULL != option_hdr );
	//ASSERT( NULL != context );
	//ASSERT( NULL != context->tree_main );
	//ASSERT( NULL != context->tree_detail );
	//
	//tree_main = context->tree_main;
	//tree_detail = context->tree_detail;

	//option_hdr->AddressOfEntryPoint;

	//sub_tree = insert_text_in_tree( tree_main, "PE Optional Header", ( byte* )option_hdr );

	//printf( opt_hdr_desc, "PE Image base : 0x%0.8x", option_hdr->ImageBase );
	//ret = insert_text_in_tree( sub_tree, opt_hdr_desc, NULL );

	//printf( opt_hdr_desc, "PE optional header signature: 0x%0.4x", option_hdr->Magic );
	//ret = insert_text_in_tree( sub_tree, opt_hdr_desc, NULL );

	//printf( opt_hdr_desc, "PE Section alignment: 0x%0.8x", option_hdr->SectionAlignment );
	//ret = insert_text_in_tree( sub_tree, opt_hdr_desc, NULL );

	//printf( opt_hdr_desc, "PE Section alignment: 0x%0.8x", option_hdr->FileAlignment );
	//ret = insert_text_in_tree( sub_tree, opt_hdr_desc, NULL );

	//printf( opt_hdr_desc, "PE Minor subsytem version: 0x%0.8x", option_hdr->MinorSubsystemVersion );
	//ret = insert_text_in_tree( sub_tree, opt_hdr_desc, NULL );

	//printf( opt_hdr_desc, "PE Minor subsytem version: 0x%0.8x", option_hdr->MinorSubsystemVersion );
	//ret = insert_text_in_tree( sub_tree, opt_hdr_desc, NULL );

	//option_hdr->SizeOfImage;
	//option_hdr->SizeOfHeaders;
	//option_hdr->CheckSum; //CheckSumMappedFile()
	//option_hdr->SizeOfStackReserve;
	//option_hdr->SizeOfStackCommit;
	//option_hdr->SizeOfHeapReserve;
	//option_hdr->SizeOfHeapCommit;
	return 0;
}

int32 dump_obj_file( char *org_file_name, byte *file_data, dword file_data_len )
{
	return write_to_new_file_by_name( org_file_name, file_data, file_data_len );
}

int32 analyze_obj_file( obj_file_info *info, void *context )
{
	char file_path[ MAX_PATH ];
	char *path_delim;
	analyze_context *__context;

	__context = ( analyze_context* )context;
	
	strcpy( file_path, __context->file_path );

	path_delim = strrchr( file_path, '\\' );
	
	if( path_delim == NULL )
	{
		return -1;
	}

	*path_delim = '\0';

	return write_to_new_file( path_delim, info->file_name, info->file_data, info->file_data_len );
}


int32 analyze_coff_section_hdr( coff_sect_hdr *file_hdr, analyze_context *costext )
{
	return 0;
}

//
//typedef struct __coff_file_hdr{
//	unsigned short magic;
//	unsigned short sect_num;
//	unsigned long  time;
//	unsigned long  syms_offset;
//	unsigned long  syms_num;
//	unsigned short opt_hdr_size;
//	unsigned short flags;
//} coff_file_hdr;


int32 analyze_coff_file_hdr( coff_file_hdr *file_hdr, analyze_context *costext )
{
	char desc[ MAX_DESC_INFO_LEN ];

	HWND tree_main;
	HTREEITEM tree_sub;
	HTREEITEM tree_target;
	HTREEITEM ret;

	tree_main = costext->tree_main;

	tree_target = find_sub_tree_in_tree( tree_main, TVI_ROOT, LIB_FILE_TITLE, NULL );
	if( NULL == tree_target )
	{
		tree_sub = insert_text_in_tree( tree_main, TVI_ROOT, COFF_FILE_TITLE, NULL );
		if( NULL == tree_sub )
		{
			return -1;
		}

		tree_target = tree_sub;
	}

	ret = insert_text_in_tree( tree_main, tree_target, "COFF File Header", ( byte* )file_hdr );
	if( NULL == ret )
	{
		return -1;
	}

	//sprintf( desc, "Optional header size: %d", file_hdr->opt_hdr_size );
	//insert_text_in_tree( tree_sub, desc );

	//sprintf( desc, "Optional header size: %d", file_hdr->opt_hdr_size );
	//insert_text_in_tree( tree_sub, desc );

	//sprintf( desc, "Optional header size: %d", file_hdr->opt_hdr_size );
	//insert_text_in_tree( tree_sub, desc );

	//sprintf( desc

	return 0;
}


int32 analyze_lib_section2( lib_section_hdr *section2, analyze_context *context )
{ 
	char desc[ MAX_DESC_INFO_LEN ];

	int32 ret;
	HWND tree_main;
	HTREEITEM tree_target;
	HTREEITEM tree_ret;
	HTREEITEM tree_self;

	tree_main = context->tree_main;

	tree_target = find_sub_tree_in_tree( tree_main, TVI_ROOT, LIB_FILE_TITLE, NULL );
	if( NULL == tree_target )
	{
		return -1;
	}
	
	tree_self = insert_text_in_tree( tree_main, tree_target, LIB_SECTION2_TITLE, ( byte* )section2 );
	if( NULL == tree_self )
	{
		return -1;
	}

	ret = add_lib_section_desc( section2, tree_self, context );
	tree_ret = insert_text_in_tree( tree_main, tree_self, "Lib section string table", ( byte* )section2 );
	if( NULL == tree_ret )
	{
		return -1;
	}

	return 0;
}

int32 analyze_lib_section_longname( lib_section_hdr *section, analyze_context *costext )
{

	char desc[ MAX_DESC_INFO_LEN ];

	HWND tree_main;
	HTREEITEM tree_target;
	HTREEITEM tree_sub;

	tree_main = costext->tree_main;

	tree_target = find_sub_tree_in_tree( tree_main, TVI_ROOT, LIB_FILE_TITLE, 0 );
	if( NULL == tree_target )
	{
		return -1;
	}

	tree_sub = insert_text_in_tree( tree_main, tree_target, LIB_LONGNAME_SECTION_TITLE, ( byte* )section );
	if( NULL == tree_sub )
	{
		return -1;
	}

	return 0;
}

int32 analyze_lib_section_obj_file( lib_section_hdr *obj_file_sect, dword index, analyze_context *costext )
{

	char desc[ MAX_DESC_INFO_LEN ];

	HWND tree_main;
	HTREEITEM tree_target;
	HTREEITEM tree_sub;

	tree_main = costext->tree_main;

	tree_target = find_sub_tree_in_tree( tree_main, TVI_ROOT, LIB_FILE_TITLE, 0 );
	if( NULL == tree_target )
	{
		return -1;
	}

	sprintf( desc, "%s%d", LIB_OBJ_FILE_SECTION_TITLE, index + 1 );
	tree_sub = insert_text_in_tree( tree_main, tree_target, desc, ( byte* )obj_file_sect );

	if( NULL == tree_sub )
	{
		return -1;
	}

	return 0;
}

int32 analyze_lib_section1( lib_section_hdr *section1, analyze_context *context )
{
	//char desc[ MAX_DESC_INFO_LEN ];

	int32 ret;
	HWND tree_main;
	HTREEITEM tree_target;
	HTREEITEM tree_sub;
	HTREEITEM tree_self;
	HTREEITEM tree_ret;


	tree_main = context->tree_main;

	tree_sub = insert_text_in_tree( tree_main, TVI_ROOT, LIB_FILE_TITLE, NULL );

	if( NULL == tree_sub )
	{
		return -1;
	}

	tree_self = insert_text_in_tree( tree_main, tree_sub, LIB_SECTION1_TITLE, ( byte* )section1 );
	if( NULL == tree_self )
	{
		return -1;
	}

	ret = add_lib_section_desc( section1, tree_self, context );

	tree_ret = insert_text_in_tree( tree_main, tree_self, "Lib section symbol table", ( byte* )section1 );
	if( NULL == tree_ret )
	{
		return -1;
	}

	return 0;
}

int32 analzye_all_struct( struct_infos *struct_info, void *context )
{
	int ret;
	analyze_context *__context;
	struct_infos *__struct_info;
	ASSERT( NULL != struct_info );
	ASSERT( NULL != context );

	ret = 0;

	__context = ( analyze_context* )context;
	__struct_info = struct_info;

	switch( __struct_info->struct_id )
	{
	case STRUCT_TYPE_PE_DOS_HEADER:
		ret = analyze_pe_dos_header( ( PIMAGE_DOS_HEADER )__struct_info->struct_data, __context );
		break;
	case STRUCT_TYPE_PE_DOS_STUB:
		//ret = analyze_pe_dos_stub( ( byte* )__struct_info->struct_data, __context );
		break;
	case STRUCT_TYPE_PE_NT_HEADER:
		//ret = analyze_pe_nt_hdr( ( PIMAGE_FILE_HEADER )__struct_info->struct_data, __context );
		break;
	case STRUCT_TYPE_PE_OPTIONAL_HEADER:
		//ret = analyze_pe_optional_hdr( ( PIMAGE_OPTIONAL_HEADER )__struct_info->struct_data, __context );
		break;
	case STRUCT_TYPE_LIB_SECTION1:
		ret = analyze_lib_section1( ( lib_section_hdr* )__struct_info->struct_data, __context );
		break;
	case STRUCT_TYPE_LIB_SECTION2:
		ret = analyze_lib_section2( ( lib_section_hdr* )__struct_info->struct_data, __context );
		break;
	case STRUCT_TYPE_LIB_SECTION_LONGNAME:
		ret = analyze_lib_section_longname( ( lib_section_hdr* )__struct_info->struct_data, __context );
		break;
	case STRUCT_TYPE_LIB_SECTION_OBJ_FILE:
		ret = analyze_lib_section_obj_file( ( lib_section_hdr* )__struct_info->struct_data, __struct_info->struct_context, __context );
		break;
	case STRUCT_TYPE_COFF_FILE_HEADER:
		ret = analyze_coff_file_hdr( ( coff_file_hdr* )__struct_info->struct_data, __context );
		break;
	case STRUCT_TYPE_COFF_SECTION_HEADER:
		ret = analyze_coff_section_hdr(  ( coff_sect_hdr* )__struct_info->struct_data, __context );
		break;
	default:
		ASSERT( FALSE );	
		ret = -1;
		break;
	}

	return ret;
}

int when_func_code_finded( code_infos* code_info, void *context )
{
	ASSERT( NULL != context );
	sym_org_data *org_code = ( sym_org_data* )context;

	if( NULL != org_code->sym_data && 0 != org_code->sym_data_len )
	{
		if( 0 <= mem_submem( org_code->sym_data, org_code->sym_data_len, code_info->func_code, code_info->func_code_len ) )
		{
			::MessageBox( NULL, code_info->func_name, NULL, NULL );
		}
	}
	return 0;
}

int when_find_lib_func_name( sym_infos* sym_info, void *context )
{
	CString strAddLine;
	CString strText;
	CRichEditCtrl *pRichEdit;
	ASSERT( NULL != sym_info );
	if( NULL == sym_info->sym_name )
	{
		return -1;
	}
	
	if( NULL == strstr( sym_info->sym_name, g_szFilter ) )
	{
		return -1;
	}	

	//	if( NULL != strstr( sym_info->sym_name, "/" ) )
	//{
	//	int kk = 0;
	//	//return -1;
	//}	
	//pRichEdit = ( CRichEditCtrl *)g_pDlg->GetDlgItem( IDC_EDIT_OUTPUT );
	//
	//pRichEdit->GetWindowText( strText );
	//strAddLine.Format( "%s #%d\r\n", sym_info->sym_name, 0 );

	//strText += strAddLine;

	//pRichEdit->SetWindowText( strText );
	return 0;
}

int32 on_main_tree_item_rclick( file_analyzer *analyzer )
{
	int32 ret;
	dword seled_menu_id;
	TVITEM tvi;
	HTREEITEM seled_item;
	char seled_file_path[ MAX_PATH ];
	char str_geted[ MAX_TREE_ITEM_TITLE_LEN ];
	analyze_context *context;

	context = ( analyze_context* )analyzer->context;

	seled_item = TreeView_GetSelection( context->tree_main );
	if( NULL == seled_item )
	{
		return 0;
	}

	memset( &tvi, 0, sizeof( tvi ) );
	tvi.mask = TVIF_TEXT | TVIF_PARAM;
	tvi.hItem = seled_item;
	tvi.pszText = str_geted;
	tvi.cchTextMax = MAX_TREE_ITEM_TITLE_LEN;

	ret = TreeView_GetItem( context->tree_main, &tvi );
	if( FALSE == ret )
	{
		return -1;
	}

/*	if( NULL != strstr( str_geted, LIB_SECTION1_TITLE ) )
	{

	}
	else if( NULL != strstr( str_geted, LIB_SECTION2_TITLE ) )
	{

	}
	else if( NULL != strstr( str_geted, LIB_LONGNAME_SECTION_TITLE ) )
	{

	}
	else */if( NULL != strstr( str_geted, LIB_OBJ_FILE_SECTION_TITLE ) )
	{
		seled_menu_id = SendMessage( context->main_wnd, WM_DO_UI_WORK, 0, 0 );

		if( seled_menu_id != MENU_ITEM_ID_DUMP_OBJ )
		{
			return 0;
		}

		ret = open_file_dlg( context->main_wnd, seled_file_path, MAX_PATH, 1 );
		if( 0 > ret )
		{
			return -1;
		}

		lib_section_hdr *info;
		info = ( lib_section_hdr* )tvi.lParam;
		
		dump_obj_file( seled_file_path, ( byte* )info + sizeof( lib_section_hdr ), atoi( info->size ) );
	}

	return 0;
}

int32 on_detail_tree_item_seled( HTREEITEM item_seled, file_analyzer *analyzer )
{
	int32 ret;
	TVITEM tvi;
	char str_geted[ MAX_TREE_ITEM_TITLE_LEN ];
	analyze_context *context;

	context = ( analyze_context* )analyzer->context;

	memset( &tvi, 0, sizeof( tvi ) );
	tvi.hItem = item_seled;
	tvi.pszText = str_geted;
	tvi.cchTextMax = MAX_TREE_ITEM_TITLE_LEN;

	ret = TreeView_GetItem( context->tree_main, &tvi );
	if( FALSE == ret )
	{
		return -1;
	}

	if( NULL != strstr( str_geted, LIB_SECTION1_TITLE ) )
	{

	}
	else if( NULL != strstr( str_geted, LIB_SECTION2_TITLE ) )
	{

	}
	else if( NULL != strstr( str_geted, LIB_LONGNAME_SECTION_TITLE ) )
	{

	}
	else if( NULL != strstr( str_geted, LIB_OBJ_FILE_SECTION_TITLE ) )
	{

	}
	return 0;
}

int32 on_main_tree_item_seled( HTREEITEM item_seled, file_analyzer *analyzer )
{
	analyze_context *context;

	context = ( analyze_context* )analyzer->context;

	
	return 0;
}

dword CALLBACK thread_analyze_file( LPVOID param )
{
	int32 ret;
	MSG msg;
	analyze_context *context;

	ASSERT( NULL != param );
	context = ( analyze_context* )param;

	ASSERT( '\0' != context->file_path[ 0 ] );

	SetEvent( context->start_event );

	context->analyzer.strs_analyze = when_find_lib_func_name;
	context->analyzer.code_analyze = when_func_code_finded;
	context->analyzer.syms_analyze = when_find_lib_func_name;
	context->analyzer.struct_analyze = analzye_all_struct;
	context->analyzer.obj_file_analyze = analyze_obj_file;
	context->analyzer.error_handler = error_handle;
	context->analyzer.context = context;

	while( TRUE )
	{
		ret = ::GetMessage( &msg, ( HWND )0xffffffff, 0, NULL );
		if( FALSE == ret )
		{
			goto exit_thread;
		}

		ASSERT( NULL == msg.hwnd );

		switch( msg.message )
		{
		case WM_START_FILE_ANALYZE:
			init_analyzing( context->file_path, &context->analyzer );
			break;
		case WM_MAIN_TREE_ITEM_SELED:
			on_main_tree_item_seled( ( HTREEITEM )msg.lParam, &context->analyzer );
			break;
		case WM_DETAIL_TREE_ITEM_SELED:
			on_detail_tree_item_seled( ( HTREEITEM )msg.lParam, &context->analyzer );
			break;
		case WM_MAIN_TREE_ITEM_RCLICK:
			on_main_tree_item_rclick( &context->analyzer );
			break;
		default:
			break;
		}
	}

exit_thread:
	ExitThread( 0 );
	return 0;
}

int32 exit_work_thread( analyze_context *context )
{
	int32 ret;
	dword wait_ret;
	g_bStop = TRUE;
	
	ASSERT( NULL != context );
	ASSERT( NULL != context->analyze_thread );

	for( ; ; )
	{
		ret = PostThreadMessage( context->thread_id, WM_CLOSE, 0, 0 );
		if( TRUE == ret )
		{
			break;
		}
	}
	//ASSERT( FALSE != ret );

	wait_ret = WaitForSingleObject( context->analyze_thread, 2000 );
	if( wait_ret != WAIT_OBJECT_0 )
	{
		TerminateThread( context->analyze_thread, 0 );
	}

	if( NULL != context->analyzer.all_file_data )
	{
		release_file_data( context->analyzer.all_file_data );
	}
	return 0;
}

void CpeanalyzerDlg::OnBnClickedOk()
{
	int32 i;
	int32 ret;
	dword wait_ret;
	HWND tree_main;
	HWND tree_detail;
	HWND edit_file_path;

	tree_main = ( HWND )::GetDlgItem( m_hWnd, IDC_TREE_MAIN );
	tree_detail = ( HWND )::GetDlgItem( m_hWnd, IDC_TREE_DETAIL );
	edit_file_path = ( HWND )::GetDlgItem( m_hWnd, IDC_EDIT_FILE_PATH );

	analyzing_context.main_wnd = m_hWnd;
	analyzing_context.tree_main = tree_main;
	analyzing_context.tree_detail = tree_detail;
	::GetWindowText( edit_file_path, analyzing_context.file_path, sizeof( analyzing_context.file_path ) );
	if( '\0' == analyzing_context.file_path[ 0 ] )
	{
		::MessageBox( NULL, "Please input the name the analyzing file\n", "Error", NULL );
		return;
	}

	analyzing_context.start_event = CreateEvent( NULL, FALSE, FALSE, NULL );
	if( NULL == analyzing_context.start_event )
	{
		return;
	}

	analyzing_context.analyze_thread = CreateThread( NULL, 0, thread_analyze_file, &analyzing_context, NULL, &analyzing_context.thread_id );
	if( NULL == analyzing_context.analyze_thread )
	{
		return;
	}

	wait_ret = WaitForSingleObject( analyzing_context.start_event, INFINITE );
	if( WAIT_OBJECT_0 != wait_ret )
	{
		return;
	}

	for( ; ; )
	{
		ret = ::PostThreadMessage( analyzing_context.thread_id, WM_START_FILE_ANALYZE, 0, 0 );
		if( TRUE == ret )
		{
			break;
		}
	}

	if( FALSE == ret )
	{
		exit_work_thread( &analyzing_context );
	}
}

void CpeanalyzerDlg::OnBnClickedButtonSelFile()
{
	int32 ret;
	HWND edit;
	char file_name[ MAX_PATH ];
	
	edit = ::GetDlgItem( m_hWnd, IDC_EDIT_FILE_PATH );
	ASSERT( NULL != edit );

	ret = open_file_dlg( m_hWnd, file_name, MAX_PATH, 0 );
	if( 0 > ret )
	{
		::SetWindowText( edit, "" );
	}

	::SetWindowText( edit, file_name );
}

void CpeanalyzerDlg::OnBnClickedCancel()
{
	// TODO: Add your control notification handler code here
	
	if( analyzing_context.analyze_thread == NULL )
		return;

	exit_work_thread( &analyzing_context );

	OnCancel();
}

void CpeanalyzerDlg::OnBnClickedStopAnalyze()
{
	// TODO: 在此添加控件通知处理程序代码

	if( analyzing_context.analyze_thread == NULL )
		return;

	exit_work_thread( &analyzing_context );
}

void CpeanalyzerDlg::OnTvnSelchangedTreeMain(NMHDR *pNMHDR, LRESULT *pResult)
{
	int32 ret;
	LPNMTREEVIEW pNMTreeView = reinterpret_cast<LPNMTREEVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码

	ret = PostThreadMessage( analyzing_context.thread_id, WM_MAIN_TREE_ITEM_SELED, ( WPARAM )&pNMTreeView->itemOld, ( LPARAM )&pNMTreeView->itemNew );
	if( FALSE == ret )
	{
		exit_work_thread( &analyzing_context );
	}
	*pResult = 0;
}

void CpeanalyzerDlg::OnTvnSelchangedTreeDetail(NMHDR *pNMHDR, LRESULT *pResult)
{
	int32 ret;
	LPNMTREEVIEW pNMTreeView = reinterpret_cast<LPNMTREEVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码

	ret = PostThreadMessage( analyzing_context.thread_id, WM_DETAIL_TREE_ITEM_SELED, ( WPARAM )&pNMTreeView->itemOld, ( LPARAM )&pNMTreeView->itemNew );
	if( FALSE == ret )
	{
		exit_work_thread( &analyzing_context );
	}
	*pResult = 0;
}

LRESULT CpeanalyzerDlg::OnDoUIWork( WPARAM wParam, LPARAM lParam )
{
	return create_context_menu( m_hWnd );
}

void CpeanalyzerDlg::OnRClientTreeMain( NMHDR *pNMHDR, LRESULT *pResult )
{
	POINT cur_pt;
	int32 ret;
	//TVHITTESTINFO HitTestInfo;

	//GetCursorPos( &HitTestInfo.pt );
	//::ScreenToClient( pNMHDR->hwndFrom, &HitTestInfo.pt );
	//TreeView_HitTest( pNMHDR->hwndFrom, &HitTestInfo );

	//if( NULL == HitTestInfo.hItem || 0 == ( TVHT_ONITEM & HitTestInfo.flags ) )
	//{
	//	goto __return;
	//}

	ret = PostThreadMessage( analyzing_context.thread_id, WM_MAIN_TREE_ITEM_RCLICK, ( WPARAM )NULL, ( LPARAM )NULL );
	if( FALSE == ret )
	{
		exit_work_thread( &analyzing_context );
	}
	
__return:
	*pResult = 0;
}

void CpeanalyzerDlg::OnMeasureItem(int nIDCtl, LPMEASUREITEMSTRUCT lpMeasureItemStruct)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值

	//lpMeasureItemStruct->itemHeight = 10;
	//lpMeasureItemStruct->itemWidth = 30;
	CDialog::OnMeasureItem(nIDCtl, lpMeasureItemStruct);
}

void CpeanalyzerDlg::OnInitMenuPopup(CMenu* pPopupMenu, UINT nIndex, BOOL bSysMenu)
{
	CDialog::OnInitMenuPopup(pPopupMenu, nIndex, bSysMenu);

	// TODO: 在此处添加消息处理程序代码
}
