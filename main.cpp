#include <stdio.h>
#include <stdlib.h>
#include "npga.h"

// ��uint32_t���͵�IP��ַת��Ϊ�ַ�����ʽ��IP��ַ
void uint32_to_ip(uint32_t ip_address, char* buffer, size_t buffer_size) {
    struct in_addr addr;
    addr.s_addr = ntohl(ip_address);
    inet_ntop(AF_INET, &addr, buffer, buffer_size);
}

// ��ʱ���ת��Ϊ�ɶ����ַ�����ʽ
void print_readable_time(uint32_t timestamp) {
    time_t rawtime = (time_t)timestamp;
    struct tm * timeinfo;
    char buffer[80];

    timeinfo = localtime(&rawtime);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);

    printf("time_stamp: %s\n", buffer);
}

// �ص���������
void packet_analysis_callback(const RTPS_PacketInfo *pInfo, const unsigned char *packet_data, int packet_len) {
    // ���� pInfo �� npga_info.packet_info
    npga_info.packet_info.timeStamp = pInfo->timeStamp;
	npga_info.packet_info.srcAddress = pInfo->srcAddress;
	npga_info.packet_info.dstAddress = pInfo->dstAddress;
	npga_info.packet_info.srcPort = pInfo->srcPort;
	npga_info.packet_info.dstPort = pInfo->dstPort;
    // Ϊ�µ����ݰ������ڴ�
    npga_info.packet_data = (unsigned char*)malloc(packet_len);
    if (npga_info.packet_data == NULL) {
        // �ڴ����ʧ�ܣ��������
        printf("Memory allocation failed!\n");
        return;
    }
    // �������ݵ� npga_info
    memcpy(npga_info.packet_data, packet_data, packet_len);
    npga_info.packet_len = packet_len;

    // ���������ڴ洢IP��ַ�ַ���
    char src_addr[INET_ADDRSTRLEN];
    char dst_addr[INET_ADDRSTRLEN];
	print_readable_time(npga_info.packet_info.timeStamp);
    // ת������ӡIP��ַ
    uint32_to_ip(npga_info.packet_info.srcAddress, src_addr, sizeof(src_addr));
    uint32_to_ip(npga_info.packet_info.dstAddress, dst_addr, sizeof(dst_addr));
    printf("src_addr: %s\n", src_addr);
    printf("src_port: %u\n", npga_info.packet_info.srcPort);
    printf("dst_addr: %s\n", dst_addr);
    printf("dst_port: %u\n", npga_info.packet_info.dstPort);
    // ��ӡ packet_data ������
    printf("packet_len:%d\n", npga_info.packet_len);

    printf("packet_data: ");
    for (int i = 0; i < npga_info.packet_len; i++) {
        printf("%02x ", npga_info.packet_data[i]);
    }
    printf("\n============================================RTPS\n");
}

// �ص���������
void packet_udp_callback(const UDP_PacketInfo *pInfo, const unsigned char *packet_data, int packet_len) {
    // ���� pInfo �� npga_info.packet_info
    npga_info.packet_info.timeStamp = pInfo->timeStamp;
	npga_info.packet_info.srcAddress = pInfo->srcAddress;
	npga_info.packet_info.dstAddress = pInfo->dstAddress;
	npga_info.packet_info.srcPort = pInfo->srcPort;
	npga_info.packet_info.dstPort = pInfo->dstPort;
    // Ϊ�µ����ݰ������ڴ�
    npga_info.packet_data = (unsigned char*)malloc(packet_len);
    if (npga_info.packet_data == NULL) {
        // �ڴ����ʧ�ܣ��������
        printf("Memory allocation failed!\n");
        return;
    }
    // �������ݵ� npga_info
    memcpy(npga_info.packet_data, packet_data, packet_len);
    npga_info.packet_len = packet_len;

    // ���������ڴ洢IP��ַ�ַ���
    char src_addr[INET_ADDRSTRLEN];
    char dst_addr[INET_ADDRSTRLEN];
	print_readable_time(npga_info.packet_info.timeStamp);
    // ת������ӡIP��ַ
    uint32_to_ip(npga_info.packet_info.srcAddress, src_addr, sizeof(src_addr));
    uint32_to_ip(npga_info.packet_info.dstAddress, dst_addr, sizeof(dst_addr));
    printf("src_addr: %s\n", src_addr);
    printf("src_port: %u\n", npga_info.packet_info.srcPort);
    printf("dst_addr: %s\n", dst_addr);
    printf("dst_port: %u\n", npga_info.packet_info.dstPort);
    // ��ӡ packet_data ������
    printf("packet_len:%d\n", npga_info.packet_len);

    printf("packet_data: ");
    for (int i = 0; i < npga_info.packet_len; i++) {
        printf("%02x ", npga_info.packet_data[i]);
    }
    printf("\n============================================UDP\n");
}

// ��ȡ NPGA_PacketInfo �ĺ���
NPGA_PacketInfo* npga_getPacketInfo() {
    return &npga_info;
}

// �����̺߳���
DWORD WINAPI capture_thread_func(LPVOID arg) {
    if (npga_start() != 0) {
        fprintf(stderr, "Failed to start capture session\n");
        return 1;
    }
    return 0;
}

int main()
{
    char* devs_info = npga_get_devs();
    if (devs_info != NULL) {
        printf("%s", devs_info);
        free(devs_info);
    }

	if (npga_new("/Device/NPF_{6BF06E61-3D5C-4616-9006-A6E9E87B2DE6}")!=0 ) {
		fprintf(stderr, "init failed\n");
		return -1;
	}
	

	//// ���ö˿�
 //   if (npga_setPort("/Device/NPF_{6BF06E61-3D5C-4616-9006-A6E9E87B2DE6}") != 0) {
 //       fprintf(stderr, "Failed to set port\n");
 //       npga_delete();
 //       return -1;
 //   }

	//

 //   // ��ȡ�˿�
 //   char *port = npga_getPort();
 //   if (port) {
 //       printf("Port: %s\n", port);
 //   } else {
 //       fprintf(stderr, "Port not set\n");
 //   }

	

	 ////���ý���·��
  //  if (npga_setFilePort("D:/capturedFiles/FastDDS_Selftest_RTPD_Data.pcapng") != 0) {
  //      fprintf(stderr, "Failed to set parse pcap file\n");
  //      npga_delete();
  //      return -1;
  //  }

	

	// ���ô洢·����ǰ׺
    if (npga_setPcapPrefix("D:/capturedFiles", "prefix") != 0) {
        fprintf(stderr, "Failed to set pcap prefix\n");
        npga_delete();
        return -1;
    }
	
    // ���ô洢ʱ����
    if (npga_setPcapInterval(30) != 0) {
        fprintf(stderr, "Failed to set pcap interval\n");
        npga_delete();
        return -1;
    }
	
    // ��ȡ�洢ʱ����
    int interval = npga_getPcapInterval();
    printf("Pcap interval: %d seconds\n", interval);
	
	// ���ù��˹���
    if (npga_setFilter("udp port 8080") != 0) {
        fprintf(stderr, "Failed to set filter\n");
        npga_delete();
        return -1;
    }
	 
    // ��ȡ���˹���
    char *filter = npga_getFilter();
    if (filter) {
        printf("Filter: %s\n", filter);
    } else {
        fprintf(stderr, "Filter not set\n");
    }

	//// ��ӡȷ��
 //   if (npga->parseFile) {
 //       printf("parse file: %s\n", npga->parseFile);
 //   } else {
 //       fprintf(stderr, "parse Pcap file not set\n");
 //   }

	//if (npga->path && npga->prefix) {
 //       printf("Pcap path: %s\n", npga->path);
 //       printf("Pcap prefix: %s\n", npga->prefix);
 //   } else {
 //       fprintf(stderr, "Pcap path or prefix not set\n");
 //   }

	// ���ûص�����
    npga_setCallBack(packet_analysis_callback, 1);
	npga_setUDPCallBack(packet_udp_callback, 1);


	// ��ȡ NPGA_PacketInfo
    NPGA_PacketInfo *npga_info = npga_getPacketInfo();

    // ���������߳�
    HANDLE capture_thread = NULL;
    int thread_created = 0;

    // ����̨�������
    char command;
    printf("Enter 's' to start, 'p' to pause, 'r' to resume, 'e' to stop:\n");
    while (1) {
        command = getchar(); // ��ȡ�û�����
        if (command == 's') {
            // ��������Ự
            if (!thread_created) {
                capture_thread = CreateThread(NULL, 0, capture_thread_func, NULL, 0, NULL);
                if (capture_thread == NULL) {
                    fprintf(stderr, "Failed to create capture thread\n");
                    npga_delete();
                    return -1;
                }
                thread_created = 1;
                printf("Capture session started\n");	
            }
        } else if (command == 'p') {
            // ��ͣ
            npga_pause();
            printf("Capture session paused\n");
        } else if (command == 'r') {
            // �ָ�
            npga_resume();
            printf("Capture session resumed\n");
        } else if (command == 'e') {
            // ֹͣ
            npga_stop();
            printf("Capture session stopped\n");
            break;
        }
        // ������뻺����
        while (getchar() != '\n');
    }

    // �ȴ������߳̽���
    if (thread_created) {
        WaitForSingleObject(capture_thread, INFINITE);
        CloseHandle(capture_thread);
    }

	npga_delete();
	system("PAUSE"); 
	return 0;
}