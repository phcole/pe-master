// pe-analyzer.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error �ڰ������� PCH �Ĵ��ļ�֮ǰ������stdafx.h��
#endif

#include "resource.h"		// ������


// CpeanalyzerApp:
// �йش����ʵ�֣������ pe-analyzer.cpp
//

class CpeanalyzerApp : public CWinApp
{
public:
	CpeanalyzerApp();

// ��д
	public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CpeanalyzerApp theApp;
