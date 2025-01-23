
// PEParserDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "PEParser.h"
#include "PEParserDlg.h"
#include "afxdialogex.h"
#include "log.h"
#include "struct.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#define INVALID_FILE_OFFSET 0xFFFFFFFF

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
public:
	//	CString NumToAscii(CString num);
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


// CPEParserDlg 对话框



CPEParserDlg::CPEParserDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_PEPARSER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPEParserDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TREE_FILE, m_treeFile);
	DDX_Control(pDX, IDC_LIST_DISPLAY, m_listDisplay);
	DDX_Control(pDX, IDC_LIST_FUNCTION, m_lstFunction);
	DDX_Control(pDX, IDC_LIST_MODULE, m_lstModule);
}

BEGIN_MESSAGE_MAP(CPEParserDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BTN_OK, &CPEParserDlg::OnClickedBtnOk)
	ON_NOTIFY(TVN_SELCHANGED, IDC_TREE_FILE, &CPEParserDlg::OnSelchangedTreeFile)
	ON_NOTIFY(NM_CLICK, IDC_TREE_FILE, &CPEParserDlg::OnNMClickTreeFile)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_DISPLAY, &CPEParserDlg::OnNMDblclkListDisplay)
	ON_EN_KILLFOCUS(IDC_EDITCELL, &CPEParserDlg::OnEnKillfocusEditCell)
	ON_COMMAND(IDOK, &CPEParserDlg::OnIdok)
	//ON_NOTIFY(NM_CLICK, IDC_LIST_DISPLAY, &CPEParserDlg::OnNMClickListDisplay)
	//ON_WM_SIZE()
	ON_NOTIFY(NM_CLICK, IDC_LIST_MODULE, &CPEParserDlg::OnNMClickListModule)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_DISPLAY, &CPEParserDlg::OnNMRClickListDisplay)
	ON_COMMAND(ID_ADDSEC, &CPEParserDlg::OnAddsec)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_MODULE, &CPEParserDlg::OnNMRClickListModule)
	ON_COMMAND(ID_CONTEXTMENU_ADDIMPORT, &CPEParserDlg::OnContextmenuAddimport)
END_MESSAGE_MAP()



// CPEParserDlg 消息处理程序

BOOL CPEParserDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
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

void CPEParserDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CPEParserDlg::OnPaint()
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
HCURSOR CPEParserDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



bool CPEParserDlg::CreateMapView()
{
	// Get file path from Edit Browse
	GetDlgItemText(IDC_MFCEDITBROWSE_FILEPATH, m_strFilePath);

	// Create File
	m_hFile = CreateFile(m_strFilePath.GetBuffer(),
		GENERIC_READ | GENERIC_WRITE,
		0,   //open the file with exclusive access
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (m_hFile == INVALID_HANDLE_VALUE) {
		LOGE("CreateFile");
		AfxMessageBox("Fail to create file");
		return false;
	}


	//Create a file mapping object
	m_hFileMapObj = CreateFileMapping(m_hFile,
		NULL,
		PAGE_READWRITE,
		0,
		0,
		NULL);
	if (m_hFileMapObj == NULL) {
		LOGE("CreateFileMapping");
		AfxMessageBox("Fail to create file mapping object!");
		CloseHandle(m_hFile);
		return false;
	}

	//Map the file to memory
	m_lpBaseAddress = MapViewOfFile(m_hFileMapObj,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		0);
	if (m_lpBaseAddress == NULL)
	{
		LOGE("MapViewOfFile");
		AfxMessageBox("Fail to create map view!");
		CloseHandle(m_hFileMapObj);
		CloseHandle(m_hFile);
		return false;
	}


	//	Cast the file base address to the appropriate structures and parse the headers 
	m_pDosHdr = (PIMAGE_DOS_HEADER)m_lpBaseAddress;
	m_pNtHdr = (PIMAGE_NT_HEADERS)(m_pDosHdr->e_lfanew + (BYTE*)m_lpBaseAddress);
	// check if the file is in PE format
	if (m_pDosHdr->e_magic != IMAGE_DOS_SIGNATURE || m_pNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		AfxMessageBox("Not a PE file!");
		return false;
	}
	m_pFileHdr = &(m_pNtHdr->FileHeader);
	m_pOptHdr = &(m_pNtHdr->OptionalHeader);
	if (m_pFileHdr->NumberOfSections != 0) {
		m_pSecHdr = (PIMAGE_SECTION_HEADER)((BYTE*)m_pOptHdr + m_pFileHdr->SizeOfOptionalHeader);
	}


	return true;
}




int CPEParserDlg::InitTreeCtrl()
{

	//Insert Process Name
	HTREEITEM  hProcess = m_treeFile.InsertItem(m_strFileName);

	//Insert PE structures
	//DOS Header
	HTREEITEM  hDOS = m_treeFile.InsertItem("DOS Header", NULL, NULL, hProcess);

	//NT头
	HTREEITEM  hNtHeaders = m_treeFile.InsertItem("NT Headers", NULL, NULL, hProcess);

	//File Header
	HTREEITEM  hFileHeader = m_treeFile.InsertItem("File Header", NULL, NULL, hNtHeaders);

	//Optional Header
	HTREEITEM  hOptionalHeader = m_treeFile.InsertItem("Optional Header", NULL, NULL, hNtHeaders);

	// Data Directory 
	HTREEITEM hDataDict = m_treeFile.InsertItem("Data Directories [x]", NULL, NULL, hOptionalHeader);
	//section Headers
	HTREEITEM  hSectionHeaders = m_treeFile.InsertItem("Section Headers [x]", NULL, NULL, hProcess);

	// Import Directory
	HTREEITEM hImportDict = m_treeFile.InsertItem("Import Directory", NULL, NULL, hProcess);

	//Address Converter 
	HTREEITEM hAddrConvert = m_treeFile.InsertItem("Address Converter", NULL, NULL, hProcess);

	m_treeFile.Expand(hProcess, TVE_EXPAND);
	//m_treeFile.Expand(hNtHeaders, TVE_EXPAND);




	////导出目录
	//HTREEITEM  hExprotDirect = m_treeFile.InsertItem("导出目录", NULL, NULL, hProcess);

	////重定位表
	//HTREEITEM  hRelocation = m_treeFile.InsertItem("重定位表", NULL, NULL, hProcess);

	////TLs表
	//HTREEITEM  hTLs = m_treeFile.InsertItem("TLs表", NULL, NULL, hProcess);

	////资源表
	//HTREEITEM  hResource = m_treeFile.InsertItem("资源表", NULL, NULL, hProcess);


	return 0;
}

int CPEParserDlg::InitLstFunction()
{
	// Insert Table Headers
	m_lstFunction.InsertColumn(0, "IAT (ThunkRVA)", LVCFMT_LEFT, -1);
	m_lstFunction.InsertColumn(1, "Thunk Offset", LVCFMT_LEFT, -1);
	m_lstFunction.InsertColumn(2, "ThunkValue", LVCFMT_LEFT, -1);
	m_lstFunction.InsertColumn(3, "Hint", LVCFMT_LEFT, -1);
	m_lstFunction.InsertColumn(4, "Name", LVCFMT_LEFT, -1);
	m_lstFunction.InsertColumn(5, "Ordinal", LVCFMT_LEFT, -1);
	m_lstFunction.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	AutoSizeColumns(m_lstFunction);

	return 0;
}


int CPEParserDlg::GetProcessName()
{
	//find the last "\\"
	int pos = m_strFilePath.ReverseFind('\\');
	if (pos != -1)
	{
		m_strFileName = m_strFilePath.Mid(pos + 1);
	}
	else {
		m_strFilePath = m_strFileName;
	}
	return 0;
}


void CPEParserDlg::OnClickedBtnOk()
{
	if (!CreateMapView()) {
		return;
	}
	GetProcessName();
	m_treeFile.DeleteAllItems();
	ClearListCtrl(m_listDisplay);
	ClearListCtrl(m_lstModule);
	ClearListCtrl(m_lstFunction);
	InitTreeCtrl();

}


void CPEParserDlg::OnSelchangedTreeFile(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMTREEVIEW pNMTreeView = reinterpret_cast<LPNMTREEVIEW>(pNMHDR);
	//select item on the tree
	HTREEITEM hItem = m_treeFile.GetSelectedItem();
	CString strItem = m_treeFile.GetItemText(hItem);

	if (strItem == "DOS Header")
	{
		DisplayDosHdr();
	}
	else if (strItem == "NT Headers")
	{
		DisplayNtHdrs();
	}
	else if (strItem == "File Header") {
		DisplayFileHdr();
	}
	else if (strItem == "Optional Header") {
		DisplayOptHdr();
	}
	else if (strItem == "Data Directories [x]") {
		DisplayDataDict();
	}
	else  if (strItem == "Section Headers [x]") {
		DisplaySecHdrs();
	}
	else if (strItem == "Address Converter") {
		DisplayAddrConvert();
	}
	else if (strItem == "Import Directory") {
		DisplayImportDict();
	}

	*pResult = 0;
}
/*
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

*/
int CPEParserDlg::DisplayDosHdr()
{
	ClearListCtrl(m_listDisplay);
	ClearListCtrl(m_lstModule);
	ClearListCtrl(m_lstFunction);
	m_listDisplay.ShowWindow(SW_SHOW);
	m_lstModule.ShowWindow(SW_HIDE);
	m_lstFunction.ShowWindow(SW_HIDE);


	// Insert Table Headers
	m_listDisplay.InsertColumn(0, "Member", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(1, "Offset", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(2, "Size", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(3, "Value", LVCFMT_LEFT, -1);

	char* pCur = reinterpret_cast<char*>(m_pDosHdr);
	CString strValue;
	int nOffset = 0;
	for (size_t i = 0; i < 31; i++) {
		m_listDisplay.InsertItem(i, szDosHdr[i].pName);
		CString strOffset;
		strOffset.Format(_T("%08X"), nOffset);
		m_listDisplay.SetItemText(i, 1, strOffset);

		if (szDosHdr[i].m_nSize == "WORD") {
			m_listDisplay.SetItemText(i, 2, "WORD");
			WORD value = *reinterpret_cast<WORD*>(pCur);
			strValue.Format(_T("%04X"), value);
			pCur += sizeof(WORD);
			nOffset += sizeof(WORD);
		}
		else {
			m_listDisplay.SetItemText(i, 2, "DWORD");
			DWORD value = *reinterpret_cast<DWORD*>(pCur);
			strValue.Format(_T("%08X"), value);
			pCur += sizeof(DWORD);
			nOffset += sizeof(DWORD);
		}

		m_listDisplay.SetItemText(i, 3, strValue);
	}

	AutoSizeColumns(m_listDisplay);

	return 0;
}


int CPEParserDlg::DisplayNtHdrs()
{
	ClearListCtrl(m_listDisplay);
	ClearListCtrl(m_lstModule);
	ClearListCtrl(m_lstFunction);
	m_listDisplay.ShowWindow(SW_SHOW);
	m_lstModule.ShowWindow(SW_HIDE);
	m_lstFunction.ShowWindow(SW_HIDE);
	// Insert Table Headers
	m_listDisplay.InsertColumn(0, "Member", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(1, "Offset", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(2, "Size", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(3, "Value", LVCFMT_LEFT, -1);

	m_listDisplay.InsertItem(0, "Signature");
	int nOffset = m_pDosHdr->e_lfanew;
	CString strOffset;
	strOffset.Format(_T("%08X"), nOffset);
	m_listDisplay.SetItemText(0, 1, strOffset);
	m_listDisplay.SetItemText(0, 2, "DWORD");
	DWORD value = *reinterpret_cast<DWORD*>(m_pNtHdr);
	CString strValue;
	strValue.Format(_T("%08X"), value);
	m_listDisplay.SetItemText(0, 3, strValue);
	AutoSizeColumns(m_listDisplay);
	return 0;
}


/*typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

*/

int CPEParserDlg::DisplayFileHdr()
{

	ClearListCtrl(m_listDisplay);
	ClearListCtrl(m_lstModule);
	ClearListCtrl(m_lstFunction);
	m_listDisplay.ShowWindow(SW_SHOW);
	m_lstModule.ShowWindow(SW_HIDE);
	m_lstFunction.ShowWindow(SW_HIDE);
	// Insert Table Headers
	m_listDisplay.InsertColumn(0, "Member", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(1, "Offset", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(2, "Size", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(3, "Value", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(4, "Meaning", LVCFMT_LEFT, -1);
	// offset of the file header 
	size_t nFileHdrOffset = m_pDosHdr->e_lfanew + sizeof(DWORD);
	size_t nOffset = nFileHdrOffset;
	for (int i = 0; i < 7; i++) {
		// insert name of the structure member
		m_listDisplay.InsertItem(i, szFileHdr[i].pName);

		CString strOffset;
		strOffset.Format(_T("%08X"), nOffset);
		m_listDisplay.SetItemText(i, 1, strOffset);

		// Display size and update offset for the next struct member
		CString strSize;
		CString strValue;
		if (szFileHdr[i].m_nSize == "WORD") {
			strSize = "WORD";
			//read value as word
			WORD value = *(WORD*)((BYTE*)m_pFileHdr + nOffset - nFileHdrOffset);
			strValue.Format(_T("%04X"), value);
			m_listDisplay.SetItemText(i, 3, strValue);
			//update offset for next struct member
			nOffset += sizeof(WORD);
		}
		else if (szFileHdr[i].m_nSize == "DWORD") {
			strSize = "DWORD";
			//read value as dword
			DWORD value = *(DWORD*)((BYTE*)m_pFileHdr + nOffset - nFileHdrOffset);
			strValue.Format(_T("%04X"), value);
			m_listDisplay.SetItemText(i, 3, strValue);
			//update offset for next struct member
			nOffset += sizeof(DWORD);
		}

		m_listDisplay.SetItemText(i, 2, strSize);

		if (szFileHdr[i].pName == "Machine") {
			m_listDisplay.SetItemText(i, 4, mapMachine[strValue]);
		}

	}

	AutoSizeColumns(m_listDisplay);
	return 0;
}


/*
typedef struct _IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//

	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;

	//
	// NT additional fields.
	//

	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

*/



int CPEParserDlg::DisplayOptHdr()
{

	ClearListCtrl(m_listDisplay);
	ClearListCtrl(m_lstModule);
	ClearListCtrl(m_lstFunction);
	m_listDisplay.ShowWindow(SW_SHOW);
	m_lstModule.ShowWindow(SW_HIDE);
	m_lstFunction.ShowWindow(SW_HIDE);
	// Insert Table Headers
	m_listDisplay.InsertColumn(0, "Member", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(1, "Offset", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(2, "Size", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(3, "Value", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(4, "Meaning", LVCFMT_LEFT, -1);

	// offset of the file header 
	size_t nOptHdrOffset = m_pDosHdr->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	size_t nOffset = nOptHdrOffset;
	for (int i = 0; i < 30; i++) {
		// insert name of the structure member
		m_listDisplay.InsertItem(i, szOptHdr[i].pName);

		CString strOffset;
		strOffset.Format(_T("%08X"), nOffset);
		m_listDisplay.SetItemText(i, 1, strOffset);

		// Display size and update offset for the next struct member
		CString strSize;
		CString strValue;
		if (szOptHdr[i].m_nSize == "WORD") {
			strSize = "WORD";
			//read value as word
			WORD value = *(WORD*)((BYTE*)m_pOptHdr + nOffset - nOptHdrOffset);
			strValue.Format(_T("%04X"), value);
			m_listDisplay.SetItemText(i, 3, strValue);
			//update offset for next struct member
			nOffset += sizeof(WORD);
		}
		else if (szOptHdr[i].m_nSize == "DWORD") {
			strSize = "DWORD";
			//read value as dword
			DWORD value = *(DWORD*)((BYTE*)m_pOptHdr + nOffset - nOptHdrOffset);
			strValue.Format(_T("%08X"), value);
			m_listDisplay.SetItemText(i, 3, strValue);
			//update offset for next struct member
			nOffset += sizeof(DWORD);
		}
		else if (szOptHdr[i].m_nSize == "BYTE") {
			strSize = "BYTE";
			//read value as byte
			BYTE value = *(BYTE*)((BYTE*)m_pOptHdr + nOffset - nOptHdrOffset);
			strValue.Format(_T("%02X"), value);
			m_listDisplay.SetItemText(i, 3, strValue);
			//update offset for next struct member
			nOffset += sizeof(BYTE);
		}
		m_listDisplay.SetItemText(i, 2, strSize);

		CString strMeaning;
		if (szOptHdr[i].pName == "Magic") {
			if (strValue == "010B") {
				strMeaning = "PE32";
			}
			else if (strValue == "020B") {
				strMeaning = "PE32+";
			}
			else {
				strMeaning = " ";
			}
			m_listDisplay.SetItemText(i, 4, strMeaning);
		}
		if (szOptHdr[i].pName == "AddressOfEntryPoint") {
			strMeaning = ".text";
			m_listDisplay.SetItemText(i, 4, strMeaning);
		}
		if (szOptHdr[i].pName == "Subsystem") {
			strMeaning = mapSubsystem[strValue];
			m_listDisplay.SetItemText(i, 4, strMeaning);
		}
	}

	AutoSizeColumns(m_listDisplay);
	return 0;
}


int CPEParserDlg::DisplaySecHdrs()
{
	ClearListCtrl(m_listDisplay);
	ClearListCtrl(m_lstModule);
	ClearListCtrl(m_lstFunction);
	m_listDisplay.ShowWindow(SW_SHOW);
	m_lstModule.ShowWindow(SW_HIDE);
	m_lstFunction.ShowWindow(SW_HIDE);
	// Insert Table Headers
	m_listDisplay.InsertColumn(0, "Name", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(1, "Virtual Size", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(2, "Virtual Address", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(3, "Raw Size", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(4, "Raw Address", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(5, "Reloc Address", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(6, "Linenumbers", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(7, "Relocations Number", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(8, "Linenumbers Number", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(9, "Characteristics", LVCFMT_LEFT, -1);
	AutoSizeColumns(m_listDisplay);
	int nNumOfSections = m_pFileHdr->NumberOfSections;
	if (nNumOfSections == 0) {
		return 0;
	}
	for (int i = 0; i < nNumOfSections; i++) {
		PIMAGE_SECTION_HEADER pCurSecHdr = (PIMAGE_SECTION_HEADER)((BYTE*)m_pSecHdr + sizeof(IMAGE_SECTION_HEADER) * i);
		char szName[9] = { 0 };
		memcpy(szName, pCurSecHdr->Name, 8);
		CString strName(szName);
		m_listDisplay.InsertItem(i, strName);
		CString strVirtualSize;
		strVirtualSize.Format(_T("%08X"), pCurSecHdr->Misc.VirtualSize);
		m_listDisplay.SetItemText(i, 1, strVirtualSize);
		CString strVirtualAddr;
		strVirtualAddr.Format(_T("%08X"), pCurSecHdr->VirtualAddress);
		m_listDisplay.SetItemText(i, 2, strVirtualAddr);
		CString strSizeOfRaw;
		strSizeOfRaw.Format(_T("%08X"), pCurSecHdr->SizeOfRawData);
		m_listDisplay.SetItemText(i, 3, strSizeOfRaw);
		CString strPtToRaw;
		strPtToRaw.Format(_T("%08X"), pCurSecHdr->PointerToRawData);
		m_listDisplay.SetItemText(i, 4, strPtToRaw);
		CString strPtToReloc;
		strPtToReloc.Format(_T("%08X"), pCurSecHdr->PointerToRelocations);
		m_listDisplay.SetItemText(i, 5, strPtToReloc);
		CString strPtToLineNum;
		strPtToLineNum.Format(_T("%08X"), pCurSecHdr->PointerToLinenumbers);
		m_listDisplay.SetItemText(i, 6, strPtToLineNum);
		CString strNumOfReloc;
		strNumOfReloc.Format(_T("%04X"), pCurSecHdr->NumberOfRelocations);
		m_listDisplay.SetItemText(i, 7, strNumOfReloc);
		CString strNumOfLine;
		strNumOfLine.Format(_T("%04X"), pCurSecHdr->NumberOfLinenumbers);
		m_listDisplay.SetItemText(i, 8, strNumOfLine);
		CString strCharacter;
		strCharacter.Format(_T("%08X"), pCurSecHdr->Characteristics);
		m_listDisplay.SetItemText(i, 9, strCharacter);
	}


	return 0;
}

int CPEParserDlg::DisplayDataDict()
{
	ClearListCtrl(m_listDisplay);
	ClearListCtrl(m_lstModule);
	ClearListCtrl(m_lstFunction);
	m_listDisplay.ShowWindow(SW_SHOW);
	m_lstModule.ShowWindow(SW_HIDE);
	m_lstFunction.ShowWindow(SW_HIDE);
	// Insert Table Headers
	m_listDisplay.InsertColumn(0, "Member", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(1, "Offset", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(2, "Size", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(3, "Value", LVCFMT_LEFT, -1);
	m_listDisplay.InsertColumn(4, "Section", LVCFMT_LEFT, -1);

	// offset of the data directory
	size_t nDataDictOffset = m_pDosHdr->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 96;
	size_t nOptHdrOffset = m_pDosHdr->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	size_t nOffset = nDataDictOffset;
	for (int i = 0; i < 32; i++) {
		m_listDisplay.InsertItem(i, szDataDict[i].pName);
		CString strOffset;
		strOffset.Format(_T("%08X"), nOffset);
		m_listDisplay.SetItemText(i, 1, strOffset);
		m_listDisplay.SetItemText(i, 2, "DWORD");
		CString strValue;
		DWORD value = *(DWORD*)((BYTE*)m_pOptHdr + nOffset - nOptHdrOffset);
		strValue.Format(_T("%08X"), value);
		m_listDisplay.SetItemText(i, 3, strValue);
		if (szDataDict[i].pName == "Import Table RVA" || szDataDict[i].pName == "Import Address Table (IAT) RVA") {
			m_listDisplay.SetItemText(i, 4, ".rdata");
		}
		nOffset += sizeof(DWORD);
	}

	AutoSizeColumns(m_listDisplay);
	return 0;

}

int CPEParserDlg::DisplayAddrConvert()
{
	ClearListCtrl(m_listDisplay);
	ClearListCtrl(m_lstModule);
	ClearListCtrl(m_lstFunction);
	m_listDisplay.ShowWindow(SW_SHOW);

	m_lstModule.ShowWindow(SW_HIDE);
	m_lstFunction.ShowWindow(SW_HIDE);
	// Initiate the ListCtrl 
	m_listDisplay.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	//Add the header
	m_listDisplay.InsertColumn(0, _T("Name"), LVCFMT_LEFT, 200);
	m_listDisplay.InsertColumn(1, _T("Value"), LVCFMT_LEFT, 250);
	// add name for each row
	m_listDisplay.InsertItem(0, _T("VA"));
	m_listDisplay.InsertItem(1, _T("RVA"));
	m_listDisplay.InsertItem(2, _T("File Offset"));


	return 0;
}

int CPEParserDlg::DisplayImportDict()
{
	ClearListCtrl(m_listDisplay);
	ClearListCtrl(m_lstModule);
	ClearListCtrl(m_lstFunction);

	m_lstFunction.ShowWindow(SW_SHOW);
	m_listDisplay.ShowWindow(SW_HIDE);
	m_lstModule.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
	m_lstModule.ShowWindow(SW_SHOW);
	// Insert Table Headers
	m_lstModule.InsertColumn(0, "Module Name", LVCFMT_LEFT, -1);
	m_lstModule.InsertColumn(1, "Imports", LVCFMT_LEFT, -1);
	m_lstModule.InsertColumn(2, "TimeDateStamp", LVCFMT_LEFT, -1);
	m_lstModule.InsertColumn(3, "ForwarderChain", LVCFMT_LEFT, -1);
	m_lstModule.InsertColumn(4, "Name RVA", LVCFMT_LEFT, -1);
	m_lstModule.InsertColumn(5, "FTs (IAT)", LVCFMT_LEFT, -1);

	// Get first IMAGE_IMPORT_DESCRIPTOR
	DWORD dwImportTableRVA = m_pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (dwImportTableRVA == 0) {
		AfxMessageBox("No Import Directory!");
		return 0;
	}
	// convert RVA to file offset and add to File base address (lpBaseAddress)
	m_pFirstIID = (PIMAGE_IMPORT_DESCRIPTOR)(CalFileOffset(dwImportTableRVA) + (BYTE*)m_lpBaseAddress);

	PIMAGE_IMPORT_DESCRIPTOR pIID = m_pFirstIID;
	// loop to traverse IMAGE_IMPORT_DESCRIPTOR arrays. loop ends when IID = 0
	int nRow = 0;
	while (pIID && pIID->FirstThunk && pIID->Name) {
		CString strDllName = (char*)(CalFileOffset(pIID->Name) + (BYTE*)m_lpBaseAddress);
		m_lstModule.InsertItem(nRow, strDllName);
		CString strNumOfFunc;
		strNumOfFunc.Format(_T("%d"), GetNumOfFunc(pIID));
		m_lstModule.SetItemText(nRow, 1, strNumOfFunc);
		CString strOFTs;
		strOFTs.Format(_T("%08X"), pIID->OriginalFirstThunk);
		m_lstModule.SetItemText(nRow, 2, strOFTs);
		CString strTimeStamp;
		strTimeStamp.Format(_T("%08X"), pIID->TimeDateStamp);
		CString strForwardChain;
		strForwardChain.Format(_T("%08X"), pIID->ForwarderChain);
		m_lstModule.SetItemText(nRow, 3, strForwardChain);
		CString strNameRVA;
		strNameRVA.Format(_T("%08X"), pIID->Name);
		m_lstModule.SetItemText(nRow, 4, strNameRVA);
		CString strFTs;
		strFTs.Format(_T("%08X"), pIID->FirstThunk);
		m_lstModule.SetItemText(nRow, 5, strFTs);
		nRow++;
		pIID++;
	}
	AutoSizeColumns(m_lstModule);
	return 0;
}

int CPEParserDlg::AddSections(CString strSectionName, DWORD dwSectionSize)
{
	// 1. check if space is enough to add a section header
	// required Space =  SizeOfHeaders - (DosHeader + Dos Stub + PEHeaders + sectionHeaders) > =sizeof(IMAGE_SECTION_HEADER) * 2  
	// if sizeof(IMAGE_SECTION_HEADER)  < space <= sizeof(IMAGE_SECTION_HEADER) * 2 , section could be added but there's security risk
	DWORD remainingSpace = m_pOptHdr->SizeOfHeaders - (m_pDosHdr->e_lfanew + sizeof(m_pNtHdr->Signature) +
		sizeof(m_pNtHdr->FileHeader) + m_pFileHdr->SizeOfOptionalHeader +
		(m_pFileHdr->NumberOfSections) * sizeof(IMAGE_SECTION_HEADER));
	if (remainingSpace < 2 * sizeof(IMAGE_SECTION_HEADER)) {
		AfxMessageBox("Cannot add a new section header. Try realigning the PE to a bigger File Alignment.");
		return -1;
	}

	// 2. add a new section header
	PIMAGE_SECTION_HEADER pNewSecHdr = m_pSecHdr + m_pFileHdr->NumberOfSections;
	memset(pNewSecHdr, 0, sizeof(IMAGE_SECTION_HEADER));
	// 3. add 40 (sizeof(IMAGE_SECTION_HEADER) 0x00 after the new section header to reduce security risk
	memset(pNewSecHdr + 1, 0, sizeof(IMAGE_SECTION_HEADER));
	// 4. set IMAGE_SECTION_HEADER members for the new section
	strncpy_s((char*)pNewSecHdr->Name, sizeof(pNewSecHdr->Name), CT2A(strSectionName), _TRUNCATE);
	pNewSecHdr->Misc.VirtualSize = dwSectionSize;  // size without section alignment
	//if no section exists
	if (m_pFileHdr->NumberOfSections == 0) {
		pNewSecHdr->VirtualAddress = AlignSize(m_pOptHdr->SizeOfHeaders, m_pOptHdr->SectionAlignment);
		pNewSecHdr->PointerToRawData = m_pOptHdr->SizeOfHeaders;
	}
	// last section header's address
	PIMAGE_SECTION_HEADER pLastSectionHdr = m_pSecHdr + m_pFileHdr->NumberOfSections - 1;
	pNewSecHdr->VirtualAddress = pLastSectionHdr->VirtualAddress + AlignSize(pLastSectionHdr->Misc.VirtualSize, m_pOptHdr->SectionAlignment);
	pNewSecHdr->SizeOfRawData = AlignSize(dwSectionSize, m_pOptHdr->FileAlignment);
	pNewSecHdr->PointerToRawData = pLastSectionHdr->PointerToRawData + pLastSectionHdr->SizeOfRawData;
	pNewSecHdr->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;
	// 4. Update PE headers:  change number of section headers
	m_pFileHdr->NumberOfSections += 1;
	// 5. change size of Image
	DWORD dwNewSecAlignedSize = AlignSize(dwSectionSize, m_pOptHdr->SectionAlignment);
	m_pOptHdr->SizeOfImage += dwNewSecAlignedSize;
	//6. extend file size and write new section data
	DWORD dwNewFileSize = pNewSecHdr->PointerToRawData + pNewSecHdr->SizeOfRawData;
	SetFilePointer(m_hFile, dwNewFileSize, NULL, FILE_BEGIN);
	SetEndOfFile(m_hFile);

	// unmap view of file
	if (m_lpBaseAddress) {
		UnmapViewOfFile(m_lpBaseAddress);
		m_lpBaseAddress = NULL;
	}
	// close FileMapObj
	if (m_hFileMapObj) {
		CloseHandle(m_hFileMapObj);
		m_hFileMapObj = NULL;
	}

	// Create file mapping for new file
	m_hFileMapObj = CreateFileMapping(m_hFile,
		NULL,
		PAGE_READWRITE,
		0,
		0,
		NULL);
	if (m_hFileMapObj == NULL) {
		LOGE("CreateFileMapping");
		AfxMessageBox("Failed to create new file mapping object!");
		CloseHandle(m_hFile);
		return false;
	}

	// map new file
	m_lpBaseAddress = MapViewOfFile(m_hFileMapObj,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		0);
	if (m_lpBaseAddress == NULL) {
		LOGE("MapViewOfFile");
		AfxMessageBox("Failed to map new view of file!");
		CloseHandle(m_hFileMapObj);
		CloseHandle(m_hFile);
		return false;
	}

	BYTE* pNewSecData = (BYTE*)m_lpBaseAddress + pNewSecHdr->PointerToRawData;

	memset(pNewSecData, 0, pNewSecHdr->SizeOfRawData);
	if (!FlushViewOfFile(m_lpBaseAddress, 0)) {
		AfxMessageBox("Failed to flush changes to disk.");
		return -1;
	}
	return 0;
}

int CPEParserDlg::AddImport(CString strModuleName, CStringArray& funcArray)
{
	//1.  calculate the size needed for the new section
	// calculate the length of  IMAGE_IMPORT_BY_NAME->name
	DWORD totalLen = 0;
	int count = funcArray.GetCount();
	for (int i = 0; i < count; i++) {
		totalLen += funcArray[i].GetLength() + 1;
	}
	DWORD numberOfFuncs = funcArray.GetSize();
	DWORD dwModuleNameLen = strModuleName.GetLength() + 1;
	DWORD totalSize = m_pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size  // original import table
		+ sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2  // new IID
		+ sizeof(IMAGE_THUNK_DATA) * (numberOfFuncs + 1) * 2    //IAT and INT
		+ sizeof(WORD) * numberOfFuncs   // IMAGE_IMPORT_BY_NAME-> hint
		+ totalLen	// IMAGE_IMPORT_BY_NAME-> name
		+ dwModuleNameLen;
	//2.  Add a new section with the aligned size
	AddSections(".addImport", AlignSize(totalSize, m_pOptHdr->SectionAlignment));
	// Get the address of the newly added section
	DWORD numberOfSec = m_pFileHdr->NumberOfSections;
	BYTE* pNewSec = (m_pSecHdr + numberOfSec - 1)->PointerToRawData + (BYTE*)m_lpBaseAddress;

	//3. copy PE's import table to the new section
		// Get first IMAGE_IMPORT_DESCRIPTOR
	DWORD dwImportTableRVA = m_pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD dwImportTableSize = m_pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	// if no import table, directly create one at the new section
	// if there's existing import table, copy it to the new section
	if (dwImportTableRVA != 0) {
		//Get the addres of the importa table
		m_pFirstIID = (PIMAGE_IMPORT_DESCRIPTOR)(CalFileOffset(dwImportTableRVA) + (BYTE*)m_lpBaseAddress);
		// copy import table to new section
		memcpy(pNewSec, m_pFirstIID, dwImportTableSize);
	}
	// 4. create a new IMPORT_IMPORT_DESCRIPTOR after the copied import table
	PIMAGE_IMPORT_DESCRIPTOR pNewIID = (PIMAGE_IMPORT_DESCRIPTOR)(pNewSec + dwImportTableSize - sizeof(IMAGE_IMPORT_DESCRIPTOR)); // SIZE includes the 0 filled IID. 
	// 5. add an IID filled with 0s
	memset(pNewIID + 1, 0, sizeof(PIMAGE_IMPORT_DESCRIPTOR));
	//6. Add INT and IAT
	PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(pNewIID + 2);
	PIMAGE_THUNK_DATA pIAT = pINT + numberOfFuncs + 1;
	// 7. set new IID members
	pNewIID->OriginalFirstThunk = CalRVA((BYTE*)pINT - (BYTE*)m_lpBaseAddress);
	pNewIID->FirstThunk = CalRVA((BYTE*)pIAT - (BYTE*)m_lpBaseAddress);
	// place modulename after IAT 
	BYTE* pModuleName = (BYTE*)(pIAT + numberOfFuncs + 1);
	pNewIID->Name = CalRVA(pModuleName - (BYTE*)m_lpBaseAddress);
	CT2A moduleName(strModuleName);
	strncpy_s((char*)pModuleName,  dwModuleNameLen, moduleName, _TRUNCATE);
	//strncpy_s((char*)pNewIID->Name, sizeof(pNewIID->Name), CT2A(strModuleName), _TRUNCATE);
	//8. add IMAGE_IMPORT_BY_NAME 
	PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)(pModuleName + dwModuleNameLen);
	for (int i = 0; i < numberOfFuncs; i++) {
		CT2A funcName(funcArray[i]);
		(pImportName + i)->Hint = 0;
		strncpy_s((char*)(pImportName + i)->Name, funcArray[i].GetLength() + 1, funcName, _TRUNCATE);
		//9. add RVA of IMAGE_IMPORT_BY_NAME to IAT and INT
		(pINT + i)->u1.AddressOfData = CalRVA((BYTE*)(pImportName + i) - (BYTE*)m_lpBaseAddress);
		(pIAT + i)->u1.AddressOfData = CalRVA((BYTE*)(pImportName + i) - (BYTE*)m_lpBaseAddress);
	}
	// 10. change IMAGE_DATA_DIRECTORY's VirtualAddress and size
	m_pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = CalRVA(pNewSec - (BYTE*)m_lpBaseAddress);
	m_pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	// 11. check if there's bound import table. if yes, set it to 0
	if (m_pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size != 0 || m_pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress != 0)
	{
		m_pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
		m_pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
	}
	return 0;
}

DWORD CPEParserDlg::GetNumOfFunc(PIMAGE_IMPORT_DESCRIPTOR pIID)
{
	// get first IMAGE_THUNK_DATA
	PIMAGE_THUNK_DATA pITD = (PIMAGE_THUNK_DATA)(CalFileOffset(pIID->FirstThunk) + (BYTE*)m_lpBaseAddress);
	DWORD num = 0;
	while (pITD->u1.AddressOfData != 0) {
		num++;
		pITD++;
	}
	return num;
}



int CPEParserDlg::UpdateTableValue(int nRow, CString strInput)
{
	DWORD dwInput = _tcstoul(strInput, NULL, 16);
	// calculate max VA
	DWORD dwMaxVA = m_pOptHdr->ImageBase + m_pOptHdr->SizeOfImage;
	DWORD dwMaxRVA = m_pOptHdr->SizeOfImage;
	DWORD dwMaxFO = CalMaxFileOffset();
	CString strVA;
	CString strRVA;
	CString strFileOffset;
	DWORD dwRVA = 0;
	DWORD dwVA = 0;
	DWORD dwFileOffset = 0;
	switch (nRow) {
	case 0:
		if (dwInput >= dwMaxVA || dwInput < m_pOptHdr->ImageBase) {
			AfxMessageBox("VA is out of range! ");
			m_listDisplay.SetItemText(0, 1, " ");
			return -1;
		}
		//RVA = VA -ImageBase
		dwRVA = dwInput - m_pOptHdr->ImageBase;
		dwFileOffset = CalFileOffset(dwRVA);
		strVA.Format(_T("%08X"), dwInput);
		m_listDisplay.SetItemText(0, 1, strVA);
		strRVA.Format(_T("%08X"), dwRVA);
		m_listDisplay.SetItemText(1, 1, strRVA);
		strFileOffset.Format(_T("%08X"), dwFileOffset);
		m_listDisplay.SetItemText(2, 1, strFileOffset);
		break;
	case 1:
		if (dwInput < 0 || dwInput >= dwMaxRVA) {
			AfxMessageBox("RVA is out of range! ");
			m_listDisplay.SetItemText(1, 1, " ");
			return -1;
		}
		//VA = RVA + ImageBase
		dwVA = dwInput + m_pOptHdr->ImageBase;
		dwFileOffset = CalFileOffset(dwInput);
		strVA.Format(_T("%08X"), dwVA);
		m_listDisplay.SetItemText(0, 1, strVA);
		strRVA.Format(_T("%08X"), dwInput);
		m_listDisplay.SetItemText(1, 1, strRVA);
		strFileOffset.Format(_T("%08X"), dwFileOffset);
		m_listDisplay.SetItemText(2, 1, strFileOffset);
		break;
	case 2:
		if (dwInput >= dwMaxFO || dwInput < 0) {
			AfxMessageBox("File Offset is out of range!");
			m_listDisplay.SetItemText(2, 1, " ");
			return -1;
		}
		strFileOffset.Format(_T("%08X"), dwInput);
		dwRVA = CalRVA(dwInput);
		strRVA.Format(_T("%08X"), dwRVA);
		dwVA = dwRVA + m_pOptHdr->ImageBase;
		strVA.Format(_T("%08X"), dwVA);
		m_listDisplay.SetItemText(0, 1, strVA);
		m_listDisplay.SetItemText(1, 1, strRVA);
		m_listDisplay.SetItemText(2, 1, strFileOffset);
		break;
	}
	return 0;
}

int CPEParserDlg::DisplayFunctionTable(int nRow)
{
	// index of the IID array
	int nIndex = nRow;
	//get the file offset address of the selected IID
	PIMAGE_IMPORT_DESCRIPTOR pIID = m_pFirstIID + nIndex;
	// RVA of the IAT 
	DWORD dwIATRVA = pIID->FirstThunk;
	// file offset address of the IAT
	PIMAGE_THUNK_DATA pITD = (PIMAGE_THUNK_DATA)(CalFileOffset(dwIATRVA) + (BYTE*)m_lpBaseAddress);
	int i = 0;
	while (pITD != NULL && pITD->u1.AddressOfData != 0) {
		DWORD dwThunkRVA = dwIATRVA + sizeof(IMAGE_THUNK_DATA) * i;
		CString strThunkRVA;
		strThunkRVA.Format(_T("%08X"), dwThunkRVA);
		m_lstFunction.InsertItem(i, strThunkRVA);
		CString strThunkFO;
		strThunkFO.Format(_T("%08X"), CalFileOffset(dwThunkRVA));
		m_lstFunction.SetItemText(i, 1, strThunkFO);
		DWORD dwAddressOfData = pITD->u1.AddressOfData;
		CString strThunkVal;
		strThunkVal.Format(_T("%08X"), dwAddressOfData);
		m_lstFunction.SetItemText(i, 2, strThunkVal);
		//check if function is imported by name or ordinal
		if (dwAddressOfData & IMAGE_ORDINAL_FLAG32) {
			DWORD dwOrdinal = dwAddressOfData & 0xFFFF; // lower 16 bits represent the ordinal
			CString strOrdinal;
			strOrdinal.Format(_T("%08X"), dwOrdinal);
			m_lstFunction.SetItemText(i, 5, strOrdinal);
		}
		else {
			CString strHint;
			PIMAGE_IMPORT_BY_NAME pIIBN = (PIMAGE_IMPORT_BY_NAME)(CalFileOffset(dwAddressOfData) + (BYTE*)m_lpBaseAddress);
			strHint.Format(_T("%04X"), pIIBN->Hint);
			m_lstFunction.SetItemText(i, 3, strHint);
			CString strName = pIIBN->Name;
			m_lstFunction.SetItemText(i, 4, strName);
		}
		i++;
		pITD++;
	}
	return 0;
}

DWORD CPEParserDlg::CalFileOffset(DWORD dwRVA) {
	// check if file offset is within the sections
	for (int i = 0; i < m_pFileHdr->NumberOfSections; i++) {
		// find the section that the RVA belongs to
		// VirtualAddress<=RVA<VirtualAddress+VirtualSize
		if (dwRVA >= m_pSecHdr[i].VirtualAddress &&
			dwRVA < m_pSecHdr[i].VirtualAddress + AlignSize(m_pSecHdr[i].Misc.VirtualSize, m_pOptHdr->SectionAlignment)) {
			// if dwRVA - m_pSecHdr[i].VirtualAddress > size of Raw Data  ==> can't find a corresponding file offset
			if (dwRVA - m_pSecHdr[i].VirtualAddress > m_pSecHdr[i].SizeOfRawData) {
				return INVALID_FILE_OFFSET;
			}
			// File Offset = PointerToRawData + RVA - VirtualAddress
			return m_pSecHdr[i].PointerToRawData + dwRVA - m_pSecHdr[i].VirtualAddress;
		}
	}
	// check if file offset is within the headers
	if (dwRVA < m_pOptHdr->SizeOfHeaders) {
		return dwRVA;
	}
	// if not within the headers or sections. return invalid 
	return INVALID_FILE_OFFSET;

}

DWORD CPEParserDlg::CalMaxFileOffset()
{
	// handle the situation when no section exists
	if (m_pFileHdr->NumberOfSections == 0) {
		return m_pOptHdr->SizeOfHeaders;
	}
	int numOfSec = m_pFileHdr->NumberOfSections;
	// File Size = last Section Header-> PointerToRawData + SizeOfRawData
	DWORD dwFileSize = m_pSecHdr[numOfSec - 1].PointerToRawData + m_pSecHdr[numOfSec - 1].SizeOfRawData;
	// sizeOfRawData is already aligned, so don't need to consider file alignment
	return dwFileSize;
}

DWORD CPEParserDlg::CalRVA(DWORD dwFileOffset)
{
	for (int i = 0; i < m_pFileHdr->NumberOfSections; i++) {
		// if dwFileOffset > Section Header-> pointerToRawData && <  Section Header-> pointerToRawData + SizeOfRawData
		// => fall into this section
		if (dwFileOffset >= m_pSecHdr[i].PointerToRawData && dwFileOffset < m_pSecHdr[i].PointerToRawData + m_pSecHdr[i].SizeOfRawData) {
			// RVA = Virtual Address + FileOffset - PointerToRawData
			return m_pSecHdr[i].VirtualAddress + dwFileOffset - m_pSecHdr[i].PointerToRawData;
		}

	}
	//	if not in the range of the sections, no difference between RVAand File Offset
	return dwFileOffset;
}

// if size is aligned, return size; otherwise, calculate  and return the aligned size
DWORD CPEParserDlg::AlignSize(DWORD dwSize, DWORD dwAlignSize) {
	if (dwSize % dwAlignSize == 0) {
		return dwSize;
	}
	else {
		return (dwSize / dwAlignSize + 1) * dwAlignSize;
	}
}
//void CPEParserDlg::GetFunctionsFromListBox(CStringArray& funcArray, CListBox listFunction)
//{
//	funcArray.RemoveAll();
//	int count = listFunction.GetCount();
//	for (int i = 0; i < count; i++) {
//		CString strFunc; 
//		listFunction.GetText(i, strFunc);
//		funcArray.Add(strFunc);
//	}
//}
void CPEParserDlg::AutoSizeColumns(CListCtrl& listCtrl)
{
	// get total number of columns
	int nColumnCount = listCtrl.GetHeaderCtrl()->GetItemCount();

	//traverse all column and set autosizing for all column
	for (int i = 0; i < nColumnCount; i++)
	{
		// Automatically adjusting column width
		listCtrl.SetColumnWidth(i, LVSCW_AUTOSIZE);

		// get the width of the column
		int nContentWidth = listCtrl.GetColumnWidth(i);

		// autosize the width according to the content of the headers
		listCtrl.SetColumnWidth(i, LVSCW_AUTOSIZE_USEHEADER);

		// get the width
		int nHeaderWidth = listCtrl.GetColumnWidth(i);

		// choose the larger width
		listCtrl.SetColumnWidth(i, max(nContentWidth, nHeaderWidth));
	}
}

int CPEParserDlg::ClearListCtrl(CListCtrl& listCtrl)
{
	listCtrl.DeleteAllItems();  // Remove all items

	// Remove all columns
	while (listCtrl.DeleteColumn(0))
	{
		// This loop will delete the first column repeatedly
		// until there are no more columns to delete.
	}
	return 0;


}



void CPEParserDlg::OnNMClickTreeFile(NMHDR* pNMHDR, LRESULT* pResult)
{
	// TODO: Add your control notification handler code here
	CPoint pt;
	GetCursorPos(&pt);
	ScreenToClient(&pt);

	UINT uFlags;
	HTREEITEM hItem = m_treeFile.HitTest(pt, &uFlags);

	if (hItem != NULL && (uFlags & TVHT_ONITEM)) // check if the point clicked is a valid tree node
	{
		// check if the node has child nodes
		if (m_treeFile.ItemHasChildren(hItem))
		{
			// expand the node
			m_treeFile.Expand(hItem, TVE_EXPAND);
		}
	}

	*pResult = 0;
}


void CPEParserDlg::OnNMDblclkListDisplay(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: Add your control notification handler code here
	int nRow = pNMItemActivate->iItem; // Row number
	int nCol = pNMItemActivate->iSubItem; // column number

	// if there is already a CEdit Ctrl, return 
	if (m_pEdit != nullptr) {
		delete m_pEdit;
		m_pEdit = nullptr;
	}
	if (nRow >= 0 && nRow < 3 && nCol == 1) {  // if value column is clicked
		// Create a CEdit control
		CRect rect;
		m_listDisplay.GetSubItemRect(nRow, nCol, LVIR_LABEL, rect);
		m_pEdit = new CEdit();
		m_pEdit->Create(WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, rect, &m_listDisplay,
			IDC_EDITCELL);
		// set the inital value as the current value in the cell
		CString strText = m_listDisplay.GetItemText(nRow, nCol);
		m_pEdit->SetWindowText(strText);
		m_pEdit->SetFocus();
		m_nRow = nRow;
	}
	*pResult = 0;
}

void CPEParserDlg::OnEnKillfocusEditCell()
{
	if (m_pEdit) {
		CString strInput;
		m_pEdit->GetWindowText(strInput);
		m_listDisplay.SetItemText(m_nRow, 1, strInput);

		if (UpdateTableValue(m_nRow, strInput) == -1) {
			m_pEdit->SetFocus();
			m_pEdit->SetSel(0, -1);
		}

		// delete CEdit Control
		delete m_pEdit;
		m_pEdit = nullptr;
	}

}


void CPEParserDlg::OnIdok()
{
	// TODO: Add your command handler code here

}

// 
BOOL CPEParserDlg::PreTranslateMessage(MSG* pMsg)
{
	// TODO: Add your specialized code here and/or call the base class
	if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_RETURN) {
		if (m_pEdit) {
			OnEnKillfocusEditCell();
			return true;
		}
	}
	return CDialogEx::PreTranslateMessage(pMsg);
}



//void CPEParserDlg::OnNMClickListDisplay(NMHDR* pNMHDR, LRESULT* pResult)
//{
//	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
//	// TODO: Add your control notification handler code here
//	int nRow = pNMItemActivate->iItem;
//	if (nRow < 0) {
//		return;
//	}
//	CString strModuleName = m_lstFunction.GetItemText(nRow, 0);
//
//	// Init and show m_lstFunction
//	InitLstFunction();
//	m_lstFunction.ShowWindow(SW_SHOW);
//
//
//	*pResult = 0;
//}


//void CPEParserDlg::OnSize(UINT nType, int cx, int cy)
//{
//	CDialogEx::OnSize(nType, cx, cy);
//
//	// TODO: Add your message handler code here
//	if (m_listDisplay.m_hWnd) {
//		if (m_lstFunction.IsWindowVisible()) {
//			int nHalfHeight = cy / 2;
//
//			//Adjust the position and shape of m_listDisplay
//			m_listDisplay.MoveWindow(0, 0, cx, nHalfHeight);
//
//			//Adjust the position and shape of m_lstFunction
//			if (m_lstFunction.m_hWnd) {
//				m_lstFunction.MoveWindow(0, nHalfHeight + 5, cx, cy - nHalfHeight - 5);
//			}
//		}
//		else {
//			// if m_lstFunction is hidden, m_listDisplay occupy the whole window
//			m_listDisplay.MoveWindow(0, 0, cx, cy);
//		}
//	}
//}

void CPEParserDlg::OnNMClickListModule(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: Add your control notification handler code here
	int nRow = pNMItemActivate->iItem;
	if (nRow < 0) {
		return;
	}
	//CString strModuleName = m_lstFunction.GetItemText(nRow, 0);
	ClearListCtrl(m_lstFunction);
	// Init and show m_lstFunction
	InitLstFunction();
	DisplayFunctionTable(nRow);
	AutoSizeColumns(m_lstFunction);
	*pResult = 0;
}


void CPEParserDlg::OnNMRClickListDisplay(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: Add your control notification handler code here
	// Get selected TreeCtrl node and only show context menu if the node is "section headers"
	HTREEITEM hSelectedItem = m_treeFile.GetSelectedItem();
	if (hSelectedItem == NULL) {
		*pResult = 0;
		return;
	}

	CString strNodeName = m_treeFile.GetItemText(hSelectedItem);
	if (strNodeName != _T("Section Headers [x]")) {
		// If not section headers, return
		*pResult = 0;
		return;
	}

	// Get mouse position
	CPoint pt;
	GetCursorPos(&pt);

	// show context menu
	CMenu contextMenu;
	contextMenu.LoadMenu(IDR_MENU1);
	CMenu* pSubMenu = contextMenu.GetSubMenu(0);
	if (pSubMenu) {
		pSubMenu->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, pt.x, pt.y, this);
	}
	*pResult = 0;
}


void CPEParserDlg::OnAddsec()
{
	// TODO: Add your command handler code here

	if (m_secDlg.DoModal() == IDOK) {
		CString strSectionName = m_secDlg.m_strSectionName;
		DWORD dwSectionSize = m_secDlg.m_dwSectionSize;
		AddSections(strSectionName, dwSectionSize);
		DisplaySecHdrs();
	}
}


void CPEParserDlg::OnNMRClickListModule(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: Add your control notification handler code here
	// Get mouse position
	CPoint pt;
	GetCursorPos(&pt);

	// show context menu
	CMenu contextMenu;
	contextMenu.LoadMenu(IDR_MENU2);
	CMenu* pSubMenu = contextMenu.GetSubMenu(0);
	if (pSubMenu) {
		pSubMenu->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, pt.x, pt.y, this);
	}
	*pResult = 0;
}


void CPEParserDlg::OnContextmenuAddimport()
{
	// TODO: Add your command handler code here
	if (m_addImportDlg.DoModal() == IDOK) {
		CString strModuleName = m_addImportDlg.m_strModuleName;
		//CStringArray funcArray;

		AddImport(strModuleName, m_addImportDlg.m_funcArray);
		DisplayImportDict();
	}
}
