#pragma once


// CSecAddDlg dialog

class CSecAddDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CSecAddDlg)

public:
	CSecAddDlg(CWnd* pParent = nullptr);   // standard constructor
	virtual ~CSecAddDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DLG_SECTIONADDER };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	DWORD m_dwSectionSize;
	CString m_strSectionName;
};
