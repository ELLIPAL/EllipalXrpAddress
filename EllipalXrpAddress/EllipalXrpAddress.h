
// EllipalXrpAddress.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CEllipalXrpAddressApp: 
// �йش����ʵ�֣������ EllipalXrpAddress.cpp
//

class CEllipalXrpAddressApp : public CWinApp
{
public:
	CEllipalXrpAddressApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CEllipalXrpAddressApp theApp;