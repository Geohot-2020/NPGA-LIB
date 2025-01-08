#ifndef  __NTAP_H__
#define  __NTAP_H__

#include "common.h"

// see \wireshark-1.8.4\CMakeLists.txt, #481
#define WS_VAR_IMPORT       __declspec(dllimport) extern
// see \wireshark-1.8.4\CMakeLists.txt, #482
#define WS_MSVC_NORETURN    __declspec(noreturn)

#ifdef  TRY
#undef  TRY
#endif
#ifdef  CATCH
#undef  CATCH
#endif
#ifdef  CATCH_ALL
#undef  CATCH_ALL
#endif
#ifdef  THROW
#undef  THROW
#endif

// wiretap源码头文件
#include "wiretap/wtap.h"


#define CHECK(x) if(!(x)) return FALSE;

/* \wiretap\wtap.h ---------------------------------------------------------------------*/
typedef struct wtap wtap;
typedef struct wtap_pkthdr wtap_pkthdr;

typedef wtap* (*f_wtap_open_offline) (const char *filename, int *err, gchar **err_info, gboolean do_random);
typedef gboolean (*f_wtap_read) (wtap *wth, int *err, gchar **err_info, gint64 *data_offset);
typedef const struct wtap_pkthdr* (*f_wtap_phdr) (wtap *wth);
typedef const u_char* (*f_wtap_buf_ptr) (wtap *wth);
typedef void (*f_wtap_close) (wtap *wth);
/*--------------------------------------------------------------------------------------*/

extern f_wtap_open_offline                   ws_wtap_open_offline;
extern f_wtap_read                           ws_wtap_read;
extern f_wtap_phdr                           ws_wtap_phdr;
extern f_wtap_buf_ptr                        ws_wtap_buf_ptr;
extern f_wtap_close                          ws_wtap_close;

HINSTANCE  LoadWiretapDLL(const TCHAR* szDLLPath);
BOOL  FreeWiretapDLL(HMODULE hModule);
BOOL  GetWiretapFunctions(HMODULE hDLL);

#endif /* NTAP_H_*/