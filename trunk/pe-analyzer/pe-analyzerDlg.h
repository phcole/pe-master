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

// pe-analyzerDlg.h : ͷ�ļ�
//

#pragma once

#define WM_START_FILE_ANALYZE ( WM_USER + 0x101 )
#define WM_MAIN_TREE_ITEM_SELED ( WM_USER + 0x102 )
#define WM_DETAIL_TREE_ITEM_SELED ( WM_USER + 0x103 )
#define WM_MAIN_TREE_ITEM_RCLICK ( WM_USER + 0x104 )
#define MENU_ITEM_ID_DUMP_OBJ	( 0x1001 )
#define WM_DO_UI_WORK ( WM_USER + 0x105 )

typedef struct __analyze_context
{
	char file_path[ MAX_PATH ];
	HWND main_wnd;
	HWND tree_main;
	HWND tree_detail;
	file_analyzer analyzer;
	HANDLE start_event;
	HANDLE analyze_thread;
	dword thread_id;
} analyze_context;

// CpeanalyzerDlg �Ի���
class CpeanalyzerDlg : public CDialog
{
// ����
public:
	CpeanalyzerDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_PEANALYZER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;
	analyze_context analyzing_context;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	afx_msg VOID OnBnClickedButtonSelFile();
	afx_msg void OnBnClickedStopAnalyze();
	afx_msg void OnTvnSelchangedTreeMain(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnTvnSelchangedTreeDetail(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnRClientTreeMain( NMHDR *pNMHDR, LRESULT *pResult );
	afx_msg void OnMeasureItem(int nIDCtl, LPMEASUREITEMSTRUCT lpMeasureItemStruct);
	afx_msg void OnInitMenuPopup(CMenu* pPopupMenu, UINT nIndex, BOOL bSysMenu);
	afx_msg LRESULT OnDoUIWork( WPARAM wParam, LPARAM lParam );
};
