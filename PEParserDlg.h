
// PEParserDlg.h: 头文件

#pragma once

#include <map>
#include "CSecAddDlg.h"
#include "CAddImportDlg.h"
// CPEParserDlg 对话框
class CPEParserDlg : public CDialogEx
{
// 构造
public:
	CPEParserDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PEPARSER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CTreeCtrl m_treeFile;
	CListCtrl m_listDisplay;
	CListCtrl m_lstFunction;
	CListCtrl m_lstModule;
	CEdit* m_pEdit = nullptr;
	int m_nRow;  // save the row number for CEdit control
	CString m_strFilePath;
	CString m_strFileName;
	HANDLE m_hFile;
	HANDLE m_hFileMapObj;
	// the address of the headers
	LPVOID m_lpBaseAddress; // starting address of the mapped view
	PIMAGE_DOS_HEADER m_pDosHdr = nullptr;  
	PIMAGE_NT_HEADERS m_pNtHdr = nullptr; 
	PIMAGE_FILE_HEADER m_pFileHdr = nullptr; 
	PIMAGE_OPTIONAL_HEADER m_pOptHdr = nullptr; 
	PIMAGE_SECTION_HEADER m_pSecHdr= nullptr;
	PIMAGE_IMPORT_DESCRIPTOR m_pFirstIID = nullptr;
	CSecAddDlg m_secDlg;
	CAddImportDlg m_addImportDlg;
	bool CreateMapView();
	int InitTreeCtrl();
	int InitLstFunction();
	int GetProcessName();
	afx_msg void OnClickedBtnOk();
	afx_msg void OnSelchangedTreeFile(NMHDR* pNMHDR, LRESULT* pResult);
	int DisplayDosHdr();
	int DisplayNtHdrs();
	int DisplayFileHdr();
	int DisplayOptHdr();
	int DisplaySecHdrs();
	int DisplayDataDict();
	int DisplayAddrConvert();
	int DisplayImportDict();
	int AddSections(CString strSectionName, DWORD dwSectionSize);
	int AddImport(CString strModuleName, CStringArray& funcArray);
	DWORD GetNumOfFunc(PIMAGE_IMPORT_DESCRIPTOR pIID);
	int UpdateTableValue(int nRow, CString strInput);
	int DisplayFunctionTable(int nRow);
	DWORD CalFileOffset(DWORD dwRVA);  // RVA->FileOffset
	DWORD CalMaxFileOffset();
	DWORD CalRVA(DWORD dwFileOffset);  // FileOffset-> RVA
	void AutoSizeColumns(CListCtrl& listCtrl);
	int ClearListCtrl(CListCtrl& listCtrl);
	DWORD AlignSize(DWORD dwVirtualSize, DWORD dwSecAlign);
//	void GetFunctionsFromListBox(CStringArray& funcArray, CListBox listFunction);
//	CString DwordToAscii(DWORD num);
//	CString numToAscii(CString hexString);
	afx_msg void OnNMClickTreeFile(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnNMDblclkListDisplay(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnEnKillfocusEditCell();
	afx_msg void OnIdok();
	virtual BOOL PreTranslateMessage(MSG* pMsg);

//	afx_msg void OnNMClickListDisplay(NMHDR* pNMHDR, LRESULT* pResult);
//	afx_msg void OnSize(UINT nType, int cx, int cy);
	
	afx_msg void OnNMClickListModule(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnNMRClickListDisplay(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnAddsec();
	afx_msg void OnNMRClickListModule(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnContextmenuAddimport();
};
