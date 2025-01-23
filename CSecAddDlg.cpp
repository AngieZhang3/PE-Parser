// CSecAddDlg.cpp : implementation file
//

#include "pch.h"
#include "PEParser.h"
#include "CSecAddDlg.h"
#include "afxdialogex.h"


// CSecAddDlg dialog

IMPLEMENT_DYNAMIC(CSecAddDlg, CDialogEx)

CSecAddDlg::CSecAddDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DLG_SECTIONADDER, pParent)
	, m_dwSectionSize(0)
	, m_strSectionName(_T(""))
{

}

CSecAddDlg::~CSecAddDlg()
{
}

void CSecAddDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_SECSIZE, m_dwSectionSize);
	DDX_Text(pDX, IDC_EDIT_SECNAME, m_strSectionName);
}


BEGIN_MESSAGE_MAP(CSecAddDlg, CDialogEx)
END_MESSAGE_MAP()


// CSecAddDlg message handlers
