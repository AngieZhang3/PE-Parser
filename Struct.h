#pragma once
// define the structures needed 


typedef struct _HDR {
	char* m_nSize;
	char* pName;
} HDR;

// DOS HEADER
HDR szDosHdr[31]{
	"WORD",   "e_magic",
	"WORD",   "e_cblp",
	"WORD",   "e_cp",
	"WORD",   "e_crlc",
	"WORD",   "e_cparhdr",
	"WORD",   "e_minalloc",
	"WORD",   "e_maxalloc",
	"WORD",   "e_ss",
	"WORD",   "e_sp",
	"WORD",   "e_csum",
	"WORD",   "e_ip",
	"WORD",   "e_cs",
	"WORD",   "e_lfarlc",
	"WORD",   "e_ovno",
	"WORD",   "e_res",
	"WORD",   " ",
	"WORD",   " ",
	"WORD",   " ",
	"WORD",   "e_oemid",
	"WORD",   "e_oeminfo",
	"WORD",   "e_res2",
	"WORD",   " ",
	"WORD",   " ",
	"WORD",   " ",
	"WORD",   " ",
	"WORD",   " ",
	"WORD",   " ",
	"WORD",   " ",
	"WORD",   " ",
	"WORD",   " ",
	"DWORD",  "e_lfanew",
};

// File Header
HDR szFileHdr[7]{
	"WORD", "Machine",
	"WORD", "NumberOfSections",
	"DWORD", "TimeDateStamp",
	"DWORD", "PointerToSymbolTable",
	"DWORD", "NumberOfSymbols",
	"WORD", "SizeOfOptionalHeader",
	"WORD", "Characteristics",
};



std::map<CString, CString> mapMachine = {
	{"0000","any type"},
	{"014C", "intel 386"},
	{"0184", "Alpha AXP"},
	{"0284", "Alpha 64"},
	{"01D3", "Matsushita AM33"},
	{"8664", "x64"},
	{"01C0", "ARM little endian"},
	{"AA64", "ARM64 little endian"},
	{"01C4", "ARM Thumb-2 little endian"},
	{"0EBC", "EFI byte code"},
	{"0200", "Intel Itanium processor family"},
	{"6232", "LoongArch 32-bit processor family"},
	{"6264", "LoongArch 64-bit processor family"},
	{"9041", "Mitsubishi M32R little endian"},
	{"0266", "LMIPS16"},
	{"0366", "MIPS with FPU"},
	{"0466", "MIPS16 with FPU"},
	{"01F0", "Power PC with floating point support"},
	{"0166", "MIPS little endian"},
	{"5032", "RISC-V 32-bit address space"},
	{"5064", "RISC-V 64-bit address space"},
	{"5128", "RISC-V 128-bit address space"},
	{"01A2", "Hitachi SH3"},
	{"01A3", "Hitachi SH3 DSP"},
	{"01A6", "Hitachi SH4"},
	{"01A8", "Hitachi SH5"},
	{"01C2", "Thumb"},
	{"0169", "MIPS little-endian WCE v2"},

};

//Optional Header (does not contain IMAGE_DATA_DIRECTORY
HDR szOptHdr[30]{
 "WORD", "Magic",
 "BYTE", "MajorLinkerVersion",
 "BYTE", "MinorLinkerVersion",
 "DWORD",  "SizeOfCode",
 "DWORD",  "SizeOfInitializedData",
 "DWORD",  "SizeOfUninitializedData",
 "DWORD",  "AddressOfEntryPoint",
 "DWORD",  "BaseOfCode",
 "DWORD",  "BaseOfData",
 "DWORD",  "ImageBase",
 "DWORD",  "SectionAlignment",
 "DWORD",  "FileAlignment",
 "WORD", "MajorOperatingSystemVersion" ,
 "WORD", "MinorOperatingSystemVersion" ,
 "WORD", "MajorImageVersion",
 "WORD", "MinorImageVersion",
 "WORD", "MajorSubsystemVersion",
 "WORD", "MinorSubsystemVersion",
 "DWORD", "Win32VersionValue",
 "DWORD", "SizeOfImage",
 "DWORD", "SizeOfHeaders",
 "DWORD", "CheckSum",
 "WORD", "Subsystem",
 "WORD", "DllCharacteristics",
 "DWORD", "SizeOfStackReserve",
 "DWORD", "SizeOfStackCommit",
 "DWORD", "SizeOfHeapReserve",
 "DWORD", "SizeOfHeapCommit",
 "DWORD", "LoaderFlags",
 "DWORD", "NumberOfRvaAndSizes",
};

std::map<CString, CString> mapSubsystem = {
	{"0000","unknown subsystem"},
	{"0001", "Native"},
	{"0002", "Windows GUI"},
	{"0003", "Windows CUI"},
	{"0005", " OS/2 character"},
	{"0007", "Posix character "},
	{"0008", "Native Win9x driver"},
	{"0009", "Windows CE"},
	{"000A", "EFI application"},
	{"000B", "EFI driver with boot services"},
	{"000C", "Intel Itanium processor family"},
	{"000D", "EFI driver with run-time services"},
	{"000E", "EFI ROM image"},
	{"000F", "XBOX"},
	{"0010", "Windows boot application"},

};

// image_data_directory
HDR szDataDict[32]{
	 "DWORD", "Export Table RVA",
	"DWORD",  "Export Table Size",
	 "DWORD", "Import Table RVA",
	 "DWORD", "Import Table Size",
	 "DWORD", "Resources Table RVA",
	 "DWORD", "Resources Table Size",
	"DWORD", "Exception Table RVA",
	"DWORD", "Exception Table Size",
	"DWORD", "Security Table RVA",
	"DWORD", "Security Table Size",
	"DWORD", "Base Relocation Table RVA",
	"DWORD", "Base Relocation Table Size",
	"DWORD", "Debug Directory RVA",
	"DWORD", "Debug Directory Size",
	"DWORD", "Architecure Directory RVA",
	"DWORD", "Architecure Directory Size",
	"DWORD", "Global Ptr Register RVA",
	"DWORD", "Global Ptr Register Size",
	"DWORD", "Thread Local Storage(TLS) Table RVA",
	"DWORD", "Thread Local Storage(TLS) Table Size",
	"DWORD", "Load Configuration Table RVA",
	"DWORD", "Load Configuration Table Size",
	"DWORD", "Bound Import Table RVA",
	"DWORD", "Bound Import Table Size",
	"DWORD", "Import Address Table (IAT) RVA",
	"DWORD", "Import Address Table (IAT) Size",
	"DWORD", "Delay Import Directory RVA",
	"DWORD",	"Delay Import Directory Size",
	"DWORD", "The CLR header RVA",
	"DWORD", "The CLR header Size",
	"DWORD", "Reserved",
	"DWORD", "Reserved",

};

// IMAGE_SECTION_HEADER
HDR szSecHdr[10]{
"BYTE[8]", "Name",
"DWORD", "VirtualSize",
  "DWORD", "VirtualAddress",
  "DWORD", "SizeOfRawData",
  "DWORD", "PointerToRawData",
  "DWORD", "PointerToRelocations",
  "DWORD", "PointerToLinenumbers",
  "WORD", "NumberOfRelocations",
  "WORD", "NumberOfLinenumbers",
  "DWORD", "Characteristics",
};