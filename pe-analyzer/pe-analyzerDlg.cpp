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

// pe-analyzerDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "pe-analyzer.h"
#include "pe-analyzerDlg.h"
#include ".\pe-analyzerdlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// CpeanalyzerDlg �Ի���



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


// CpeanalyzerDlg ��Ϣ�������

CpeanalyzerDlg *g_pDlg;
BOOL CpeanalyzerDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// ��\������...\���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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
	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	g_pDlg = this;
	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	
	return TRUE;  // ���������˿ؼ��Ľ��㣬���򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CpeanalyzerDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ��������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù����ʾ��
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
