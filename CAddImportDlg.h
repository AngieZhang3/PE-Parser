#pragma once


// CAddImportDlg dialog

class CAddImportDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CAddImportDlg)

public:
	CAddImportDlg(CWnd* pParent = nullptr);   // standard constructor
	virtual ~CAddImportDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ADDIMPORT_DLG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	CString m_strModuleName;
	CListBox m_editFunction;
	afx_msg void OnBnClickedCancel();
	CString m_editAddFunc;
	CStringArray m_funcArray;
	void GetFuncsFromListBox(CStringArray& funcArray);
	afx_msg void OnClickedBtnAdd();
	afx_msg void OnBnClickedOk();
};
