// CAddImportDlg.cpp : implementation file
//

#include "pch.h"
#include "PEParser.h"
#include "CAddImportDlg.h"
#include "afxdialogex.h"


// CAddImportDlg dialog

IMPLEMENT_DYNAMIC(CAddImportDlg, CDialogEx)

CAddImportDlg::CAddImportDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_ADDIMPORT_DLG, pParent)
	, m_strModuleName(_T(""))
	, m_editAddFunc(_T(""))
{

}

CAddImportDlg::~CAddImportDlg()
{
}

void CAddImportDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_Module, m_strModuleName);
	DDX_Control(pDX, IDC_LISTBOX_FUNCNAME, m_editFunction);
	DDX_Text(pDX, IDC_EDIT_ADDFUNC, m_editAddFunc);
}


BEGIN_MESSAGE_MAP(CAddImportDlg, CDialogEx)
	ON_BN_CLICKED(IDCANCEL, &CAddImportDlg::OnBnClickedCancel)
	ON_BN_CLICKED(IDC_BTN_ADD, &CAddImportDlg::OnClickedBtnAdd)
	ON_BN_CLICKED(IDOK, &CAddImportDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CAddImportDlg message handlers


void CAddImportDlg::OnBnClickedCancel()
{
	// TODO: Add your control notification handler code here
	CDialogEx::OnCancel();
}


void CAddImportDlg::GetFuncsFromListBox(CStringArray& funcArray)
{
	funcArray.RemoveAll();
	int count = m_editFunction.GetCount();
	for (int i = 0; i < count; i++) {
		CString strFunc;
		m_editFunction.GetText(i, strFunc);
		funcArray.Add(strFunc);
	}
}

void CAddImportDlg::OnClickedBtnAdd()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);
	if (!m_editAddFunc.IsEmpty()) {
		m_editFunction.AddString(m_editAddFunc);
		m_editAddFunc.Empty();
		UpdateData(FALSE);
	}
	return;
}


void CAddImportDlg::OnBnClickedOk()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);
	GetDlgItemText(IDC_EDIT_Module, m_strModuleName);
	GetFuncsFromListBox(m_funcArray);
	CDialogEx::OnOK();
}
