
// EllipalXrpAddressDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "EllipalXrpAddress.h"
#include "EllipalXrpAddressDlg.h"
#include "afxdialogex.h"
#include "bip39.h"
#include "hexutils.h"
#include "ripple.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CEllipalXrpAddressDlg 对话框



CEllipalXrpAddressDlg::CEllipalXrpAddressDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_ELLIPALXRPADDRESS_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CEllipalXrpAddressDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CEllipalXrpAddressDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CEllipalXrpAddressDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CEllipalXrpAddressDlg 消息处理程序

BOOL CEllipalXrpAddressDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CEllipalXrpAddressDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CEllipalXrpAddressDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
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
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CEllipalXrpAddressDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CEllipalXrpAddressDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
//	CDialogEx::OnOK();
	CEdit *pedt = (CEdit *)GetDlgItem(IDC_EDT_MNEMONIC);
	CString strMnemonic;
	pedt->GetWindowText(strMnemonic);
	strMnemonic =  strMnemonic.TrimLeft();
	strMnemonic = strMnemonic.TrimRight();

	if (strMnemonic.GetLength() <= 0) {
		MessageBox("please input mnemonic!");
		return;
	}

	if (mnemonic_check(strMnemonic.GetBuffer()) == 0) {
		MessageBox("invalid mnemocin!");
		return;
	}

	uint8_t seed[128] = { 0 };
	int len = mnemonic_to_entropy(strMnemonic.GetBuffer(), seed);

	char* hexseed = (char *)malloc(len/8 * 2 + 1);
	memset(hexseed, 0, len / 8 * 2 + 1);

	HexToStr((char *)hexseed, seed, len/8 );



	std::string addr, key, strseed,strprivate,strpublic;
	strseed = hexseed;
	key = getAccountSecretFromSeed(strseed);
	free(hexseed);
	addr = rippleGetAddressFromSecret(key);

	CEdit* pedtsecret = (CEdit *)GetDlgItem(IDC_EDT_SECRET);
	pedtsecret->SetWindowText(key.c_str());

	CEdit* pedtaddress = (CEdit *)GetDlgItem(IDC_EDT_ADDRESS);
	pedtaddress->SetWindowText(addr.c_str());

	strprivate = getAccountprivKeyFromSecret(key);
	CEdit* ppriatekey = (CEdit *)GetDlgItem(IDC_EDT_PRIVATE);
	ppriatekey->SetWindowText(strprivate.c_str());

	strpublic = getAccountPublicKeyFromSecret(key);
	CEdit* ppublic = (CEdit *)GetDlgItem(IDC_EDT_PUBLIC);
	ppublic->SetWindowText(strpublic.c_str());

	//MessageBox("ok!");
}
