#ifndef  __NSHARK_H__
#define  __NSHARK_H__

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


// wireshark源码头文件
#include "epan/epan.h"
#include "epan/epan_dissect.h"
#include "epan/proto.h"
#include "epan/packet_info.h"
#include "epan/frame_data.h"
#include "epan/packet.h"

#include "npga_shared.h"


#define CHECK(x) if(!(x)) return FALSE;


/* \register.h -------------------------------------------------------------------------*/
typedef void (*register_cb) (register_action_e action, const char *message, gpointer client_data);
typedef void (*f_register_all_protocols) (register_cb cb, gpointer client_data);
typedef void (*f_register_all_protocol_handoffs) (register_cb cb, gpointer client_data);
typedef void (*f_register_all_tap_listeners)(void);
/*--------------------------------------------------------------------------------------*/

/* \epan\packet.h ----------------------------------------------------------------------*/
typedef void (*f_init_dissection) (void);
typedef void (*f_cleanup_dissection) (void);
/*--------------------------------------------------------------------------------------*/

/* \epan\epan.h -------------------------------------------------------------------------*/
typedef void (*f_epan_init) (void (*register_all_protocols)(register_cb cb, gpointer client_data),
                            void (*register_all_handoffs)(register_cb cb, gpointer client_data),
                            register_cb cb,
                            void *client_data,
                            void (*report_failure)(const char *, va_list),
                            void (*report_open_failure)(const char *, int, gboolean),
                            void (*report_read_failure)(const char *, int));
typedef void (*f_epan_cleanup) (void);
typedef epan_dissect_t* (*f_epan_dissect_new) (gboolean create_proto_tree,
                                            gboolean proto_tree_visible);
typedef void (*f_epan_dissect_run) (epan_dissect_t *edt, void* pseudo_header,
                            const guint8* data, frame_data *fd, column_info *cinfo);
typedef void (*f_epan_dissect_free) (epan_dissect_t* edt);
typedef void (*f_epan_dissect_fill_in_columns) (epan_dissect_t *edt);
/*--------------------------------------------------------------------------------------*/

/* \epan\proto.h -----------------------------------------------------------------------*/
typedef void (*f_proto_item_fill_label) (field_info *fi, gchar *label_str);
/*--------------------------------------------------------------------------------------*/

typedef void (*f_setRTPS2DataCallback)	(RTPSPacketAnalysisCallback callback, int type);
typedef void (*f_setUDPDataCallback)	(UDPPacketAnalysisCallback callback, int type);
typedef void (*f_npga_init_index_table)	(void);
typedef void (*f_npga_init_rate_entry)	(uint32_t ip, uint16_t length, int rate, int truncate_len);




extern f_epan_init                            ws_epan_init;
extern f_epan_cleanup                        ws_epan_cleanup;
extern f_register_all_protocols                ws_register_all_protocols;
extern f_register_all_protocol_handoffs        ws_register_all_protocol_handoffs;
extern f_init_dissection                    ws_init_dissection;
extern f_cleanup_dissection                    ws_cleanup_dissection;
extern f_epan_dissect_new                    ws_epan_dissect_new;
extern f_epan_dissect_run                    ws_epan_dissect_run;
extern f_epan_dissect_free                    ws_epan_dissect_free;
extern f_proto_item_fill_label                ws_proto_item_fill_label;

extern f_setRTPS2DataCallback					ws_setRTPS2DataCallback;
extern f_setUDPDataCallback					ws_setUDPDataCallback;
extern f_npga_init_index_table					ws_npga_init_index_table;
extern f_npga_init_rate_entry					ws_npga_init_rate_entry;

HINSTANCE  LoadWiresharkDLL(const TCHAR* szDLLPath);
BOOL  FreeWiresharkDLL(HMODULE hModule);
BOOL  GetWiresharkFunctions(HMODULE hDLL);

#endif /* NSHARK_H_ */