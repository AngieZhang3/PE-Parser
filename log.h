#pragma once

#include <stdio.h>
#include <afx.h>

#define DEBUG
#ifdef DEBUG
#define LOGD(fmt, ...)  printf(fmt, __VA_ARGS__)
#else
#define LOGD(fmt, ...) 
#endif

#define LOGI(func)  { \
    CString strInfo; \
    strInfo.Format("[PEParser][+] %-20s %s ok\n", __FUNCTION__,func);\
  OutputDebugString(strInfo);  \
}


#define LOGE(func)  { \
  LPVOID lpMsgBuf = GetErrorMsg(); \
CString strError; \
  strError.Format("[PEParser][-] %-20s %s Error:%-6d %s file:%s line:%d\n", \
       __FUNCTION__, \
       func, \
       GetLastError(), \
       (char*)lpMsgBuf, \
       __FILE__,  \
       __LINE__); \
    OutputDebugString(strError); \
  LocalFree(lpMsgBuf);\
}


#define LOGW(func)  { \
  LPVOID lpMsgBuf = GetErrorMsg(); \
CString strWarning;\
strWarning.Format("[PEParser][-] %-20s %s Error:%-6d %s file:%s line:%d\n", \
    __FUNCTION__, \
    func, \
    GetLastError(), \
    (char*)lpMsgBuf, \
    __FILE__, \
    __LINE__);\
  OutputDebugString(strWarning);\
  LocalFree(lpMsgBuf);\
}


LPVOID GetErrorMsg();

