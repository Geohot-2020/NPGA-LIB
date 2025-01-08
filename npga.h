#ifndef  __NPGA_H__
#define  __NPGA_H__

#include "common.h"

#include "npga_shared.h"

// 定义新的结构体 NPGA_PacketInfo 来存储回调函数的参数值
typedef struct {
    RTPS_PacketInfo packet_info;
    u_char *packet_data;
    int packet_len;
} NPGA_PacketInfo;

// 回调函数类型定义
typedef void (*RTPSPacketAnalysisCallback)(const RTPS_PacketInfo *pInfo, const u_char *packet_data, int packet_len);
typedef void (*UDPPacketAnalysisCallback)(const UDP_PacketInfo *pInfo, const u_char *packet_data, int packet_len);

// 定义全局变量来存储回调函数的参数值
static int callback_triggered = 0;

// 定义全局变量来存储回调函数的参数值
static NPGA_PacketInfo npga_info;

typedef struct
{
    int id;
    char *interface;	//接口
	char *parseFile;	//解析文件路径
	char *path;			//存储路径
    char *prefix;		//存储文件名
    int interval;		//存储间隔
	char *filter;		//过滤规则
	int is_running;		//用于表示捕获会话是否正在运行
    int is_paused;		//用于表示捕获会话是否暂停
    pcap_t *pcap_handle;
    pcap_dumper_t *pcap_dumper;
	RTPSPacketAnalysisCallback callback;	//回调函数
    int callback_type;					//回调函数类型
    RTPS_PacketInfo *packet_info;
	u_char *packet_data;
	int packet_len;	
} NpgaInstance;

#ifdef _WIN32
    #ifdef NPGALIB_EXPORTS
        #define NPGALIB_API __declspec(dllexport)
    #else
        #define NPGALIB_API __declspec(dllimport)
    #endif
#else
    #define NPGALIB_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

NPGALIB_API char* npga_get_devs();  //获取网卡列表

NPGALIB_API int npga_new(const char *interface);   //初始化
NPGALIB_API void npga_delete();   //清理资源

//NPGALIB_API int npga_setPort(const char *interface);    //设置捕获接口
//NPGALIB_API char *npga_getPort(); //获取捕获接口

NPGALIB_API int npga_setFilePort(const char *parseFile);    //设置解析路径

NPGALIB_API int npga_setPcapPrefix(const char *path, const char *prefix);   //设置存储路径
NPGALIB_API int npga_setPcapInterval(int interval); //设置存储时间间隔
NPGALIB_API int npga_getPcapInterval();   //获取存储时间间隔

NPGALIB_API int npga_setFilter(const char *filter); //设置过滤规则
NPGALIB_API char *npga_getFilter();   //获取过滤规则

NPGALIB_API int npga_start(); //开始
NPGALIB_API int npga_stop();  //结束
NPGALIB_API int npga_pause(); //暂停
NPGALIB_API int npga_resume();//恢复

NPGALIB_API void npga_setCallBack(RTPSPacketAnalysisCallback callback, int type);   //RTPS回调函数
NPGALIB_API void npga_setUDPCallBack(UDPPacketAnalysisCallback callback, int type);		//UDP回调


#ifdef __cplusplus
}
#endif

#endif