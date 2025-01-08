#ifndef  __NPGA_H__
#define  __NPGA_H__

#include "common.h"

#include "npga_shared.h"

// �����µĽṹ�� NPGA_PacketInfo ���洢�ص������Ĳ���ֵ
typedef struct {
    RTPS_PacketInfo packet_info;
    u_char *packet_data;
    int packet_len;
} NPGA_PacketInfo;

// �ص��������Ͷ���
typedef void (*RTPSPacketAnalysisCallback)(const RTPS_PacketInfo *pInfo, const u_char *packet_data, int packet_len);
typedef void (*UDPPacketAnalysisCallback)(const UDP_PacketInfo *pInfo, const u_char *packet_data, int packet_len);

// ����ȫ�ֱ������洢�ص������Ĳ���ֵ
static int callback_triggered = 0;

// ����ȫ�ֱ������洢�ص������Ĳ���ֵ
static NPGA_PacketInfo npga_info;

typedef struct
{
    int id;
    char *interface;	//�ӿ�
	char *parseFile;	//�����ļ�·��
	char *path;			//�洢·��
    char *prefix;		//�洢�ļ���
    int interval;		//�洢���
	char *filter;		//���˹���
	int is_running;		//���ڱ�ʾ����Ự�Ƿ���������
    int is_paused;		//���ڱ�ʾ����Ự�Ƿ���ͣ
    pcap_t *pcap_handle;
    pcap_dumper_t *pcap_dumper;
	RTPSPacketAnalysisCallback callback;	//�ص�����
    int callback_type;					//�ص���������
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

NPGALIB_API char* npga_get_devs();  //��ȡ�����б�

NPGALIB_API int npga_new(const char *interface);   //��ʼ��
NPGALIB_API void npga_delete();   //������Դ

//NPGALIB_API int npga_setPort(const char *interface);    //���ò���ӿ�
//NPGALIB_API char *npga_getPort(); //��ȡ����ӿ�

NPGALIB_API int npga_setFilePort(const char *parseFile);    //���ý���·��

NPGALIB_API int npga_setPcapPrefix(const char *path, const char *prefix);   //���ô洢·��
NPGALIB_API int npga_setPcapInterval(int interval); //���ô洢ʱ����
NPGALIB_API int npga_getPcapInterval();   //��ȡ�洢ʱ����

NPGALIB_API int npga_setFilter(const char *filter); //���ù��˹���
NPGALIB_API char *npga_getFilter();   //��ȡ���˹���

NPGALIB_API int npga_start(); //��ʼ
NPGALIB_API int npga_stop();  //����
NPGALIB_API int npga_pause(); //��ͣ
NPGALIB_API int npga_resume();//�ָ�

NPGALIB_API void npga_setCallBack(RTPSPacketAnalysisCallback callback, int type);   //RTPS�ص�����
NPGALIB_API void npga_setUDPCallBack(UDPPacketAnalysisCallback callback, int type);		//UDP�ص�


#ifdef __cplusplus
}
#endif

#endif