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
// addsectionDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "pe-analyzer.h"
#include "addsectionDlg.h"
#include ".\addsectiondlg.h"


// CaddsectionDlg �Ի���

IMPLEMENT_DYNCREATE(CaddsectionDlg, CDialog)

CaddsectionDlg::CaddsectionDlg(void *_context, CWnd* pParent )
	: CDialog(CaddsectionDlg::IDD, pParent)
{
	context = _context; 
}

CaddsectionDlg::CaddsectionDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CaddsectionDlg::IDD, pParent)
{
}

CaddsectionDlg::~CaddsectionDlg()
{
}

void CaddsectionDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BOOL CaddsectionDlg::OnInitDialog()
{
	CDialog::OnInitDialog();
	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

BEGIN_MESSAGE_MAP(CaddsectionDlg, CDialog)
	ON_BN_CLICKED(IDOK, OnBnClickedOk)
END_MESSAGE_MAP()


// CaddsectionDlg ��Ϣ�������

void CaddsectionDlg::OnBnClickedOk()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	char text[ MAX_PATH ]; 
	char *remain; 
	PIMAGE_SECTION_HEADER section_hdr = ( PIMAGE_SECTION_HEADER )context; 

	if( section_hdr != NULL )
	{
		if( 0 > GetDlgItemText( IDC_EDIT_SECTION_CHAR, text, MAX_PATH ) )
		{
			goto __return; 
		}
		section_hdr->Characteristics = ( DWORD )strtol( text, &remain, 16 ); 

		if( 0 > GetDlgItemText( IDC_EDIT_SECTION_SIZE, text, MAX_PATH ) )
		{
			goto __return; 
		}
		section_hdr->Misc.VirtualSize = ( DWORD )strtol( text, &remain, 10 ); 
	}
__return:
	OnOK();
}
