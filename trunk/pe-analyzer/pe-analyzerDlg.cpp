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
#include "pe-analyzer.h"
#include "pe-analyzerDlg.h"
#include ".\pe-analyzerdlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


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
END_MESSAGE_MAP()


// CpeanalyzerDlg 消息处理程序

CpeanalyzerDlg *g_pDlg;
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

	GetDlgItem( IDC_EDIT_FILTER )->SetWindowText( "CString" );
	GetDlgItem( IDC_EDIT_PE_FILE_PATH )->SetWindowText( "lib_sample.lib" );
	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

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

#pragma comment( lib, "pe-master.lib" )
#include "common.h"
#include "common_analyze.h"
#include "pe_analyze.h"
#include "lib_analyze.h"

BOOL g_bStop;

#define MAX_FILTER_LEN 1024
CHAR g_szFilter[ MAX_FILTER_LEN ] = { 0 };
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

	pRichEdit = ( CRichEditCtrl *)g_pDlg->GetDlgItem( IDC_EDIT_OUTPUT );
	
	pRichEdit->GetWindowText( strText );
	strAddLine.Format( "%s #%d\r\n", sym_info->sym_name, 0 );

	strText += strAddLine;

	pRichEdit->SetWindowText( strText );
	return 0;
}

typedef struct __sym_org_data
{
	byte *sym_data;
	dword sym_data_len;
} sym_org_data;

sym_org_data g_sym_org_data;

dword CALLBACK thread_read_file_symbols( LPVOID lpParam )
{
	HWND hCtl;
	TCHAR szFilePath[ MAX_PATH ];

	hCtl = ::GetDlgItem( g_pDlg->m_hWnd, IDC_EDIT_PE_FILE_PATH );
	::GetWindowText( hCtl, szFilePath, MAX_PATH );

	hCtl = ::GetDlgItem( g_pDlg->m_hWnd, IDC_EDIT_FILTER );
	::GetWindowText( hCtl, g_szFilter, MAX_FILTER_LEN );

	coff_analyzer analyzer;
	analyzer.strs_analyze = NULL;
	analyzer.syms_analyze = when_find_lib_func_name;
	analyzer.context = &g_sym_org_data;

	//set_sym_process_func( when_find_lib_func_nam, &g_sym_org_data );
	start_analyze_file( szFilePath, &analyzer );

	return 0;
}

HANDLE g_hThread;
void CpeanalyzerDlg::OnBnClickedOk()
{
	HWND hCtl;
	hCtl = ::GetDlgItem( m_hWnd, IDC_EDIT_OUTPUT );
	::SetWindowText( hCtl, "" );

	g_hThread = CreateThread( NULL, 0, thread_read_file_symbols, this, NULL, NULL );
	if( NULL == g_hThread )
	{
		return;
	}
	
}

void CpeanalyzerDlg::OnBnClickedCancel()
{
	// TODO: Add your control notification handler code here
	//OnCancel();
	DWORD dwWaitRet;

	if( g_hThread == NULL )
		return;

	g_bStop = TRUE;

	dwWaitRet = WaitForSingleObject( g_hThread, 2000 );
	if( dwWaitRet != WAIT_OBJECT_0 )
	{
		TerminateThread( g_hThread, 0 );
	}
}
