#include "nshark.h"

f_epan_init                                ws_epan_init;
f_epan_cleanup                            ws_epan_cleanup;
f_register_all_protocols                ws_register_all_protocols;
f_register_all_protocol_handoffs        ws_register_all_protocol_handoffs;
f_init_dissection                        ws_init_dissection;
f_cleanup_dissection                    ws_cleanup_dissection;
f_epan_dissect_new                        ws_epan_dissect_new;
f_epan_dissect_run                        ws_epan_dissect_run;
f_epan_dissect_free                        ws_epan_dissect_free;
f_proto_item_fill_label                    ws_proto_item_fill_label;
f_setRTPS2DataCallback						ws_setRTPS2DataCallback;
f_setUDPDataCallback						ws_setUDPDataCallback;
f_npga_init_index_table						ws_npga_init_index_table;
f_npga_init_rate_entry						ws_npga_init_rate_entry;


HINSTANCE  LoadWiresharkDLL(const TCHAR* szDLLPath)
{
    return ::LoadLibrary(szDLLPath);
}

BOOL  FreeWiresharkDLL(HMODULE hModule)
{
    return ::FreeLibrary(hModule);
}

BOOL  GetWiresharkFunctions(HMODULE hDLL)
{
    CHECK(ws_epan_init = (f_epan_init)::GetProcAddress(hDLL, "epan_init"));
    CHECK(ws_epan_cleanup = (f_epan_cleanup)::GetProcAddress(hDLL, "epan_cleanup"));
    CHECK(ws_register_all_protocols = (f_register_all_protocols)
                    ::GetProcAddress(hDLL, "register_all_protocols"));
    CHECK(ws_register_all_protocol_handoffs = (f_register_all_protocol_handoffs)
                    ::GetProcAddress(hDLL, "register_all_protocol_handoffs"));
    CHECK(ws_init_dissection = (f_init_dissection)::GetProcAddress(hDLL, "init_dissection"));
    CHECK(ws_cleanup_dissection = (f_cleanup_dissection)::GetProcAddress(hDLL, "cleanup_dissection"));
    CHECK(ws_epan_dissect_new = (f_epan_dissect_new)::GetProcAddress(hDLL, "epan_dissect_new"));
    CHECK(ws_epan_dissect_run = (f_epan_dissect_run)::GetProcAddress(hDLL, "epan_dissect_run"));
    CHECK(ws_epan_dissect_free = (f_epan_dissect_free)::GetProcAddress(hDLL, "epan_dissect_free"));
    CHECK(ws_proto_item_fill_label = (f_proto_item_fill_label)::GetProcAddress(hDLL, "proto_item_fill_label"));
    CHECK(ws_setRTPS2DataCallback = (f_setRTPS2DataCallback)::GetProcAddress(hDLL, "setRTPS2DataCallback"));
	CHECK(ws_setUDPDataCallback = (f_setUDPDataCallback)::GetProcAddress(hDLL, "setUDPDataCallback"));
	CHECK(ws_npga_init_index_table = (f_npga_init_index_table)::GetProcAddress(hDLL, "npga_init_index_table"));
	CHECK(ws_npga_init_rate_entry = (f_npga_init_rate_entry)::GetProcAddress(hDLL, "npga_init_rate_entry"));
    return TRUE;
}