
// EllipalXrpAddressDlg.cpp : ʵ���ļ�
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


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// CEllipalXrpAddressDlg �Ի���



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


// CEllipalXrpAddressDlg ��Ϣ�������

BOOL CEllipalXrpAddressDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CEllipalXrpAddressDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
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
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CEllipalXrpAddressDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CEllipalXrpAddressDlg::OnBnClickedOk()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
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
