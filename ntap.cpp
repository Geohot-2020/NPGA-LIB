#include "ntap.h"

f_wtap_open_offline                   ws_wtap_open_offline;
f_wtap_read                           ws_wtap_read;
f_wtap_phdr                           ws_wtap_phdr;
f_wtap_buf_ptr                        ws_wtap_buf_ptr;
f_wtap_close                          ws_wtap_close;

HINSTANCE  LoadWiretapDLL(const TCHAR* szDLLPath)
{
    return ::LoadLibrary(szDLLPath);
}

BOOL  FreeWiretapDLL(HMODULE hModule)
{
    return ::FreeLibrary(hModule);
}

BOOL  GetWiretapFunctions(HMODULE hDLL)
{
	CHECK(ws_wtap_open_offline = (f_wtap_open_offline)::GetProcAddress(hDLL, "wtap_open_offline"));
    CHECK(ws_wtap_read = (f_wtap_read)::GetProcAddress(hDLL, "wtap_read"));
    CHECK(ws_wtap_phdr = (f_wtap_phdr)::GetProcAddress(hDLL, "wtap_phdr"));
    CHECK(ws_wtap_buf_ptr = (f_wtap_buf_ptr)::GetProcAddress(hDLL, "wtap_buf_ptr"));
    CHECK(ws_wtap_close = (f_wtap_close)::GetProcAddress(hDLL, "wtap_close"));

	return TRUE;
}