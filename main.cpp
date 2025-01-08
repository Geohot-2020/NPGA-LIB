#include <stdio.h>
#include <stdlib.h>
#include "npga.h"

// 将uint32_t类型的IP地址转换为字符串形式的IP地址
void uint32_to_ip(uint32_t ip_address, char* buffer, size_t buffer_size) {
    struct in_addr addr;
    addr.s_addr = ntohl(ip_address);
    inet_ntop(AF_INET, &addr, buffer, buffer_size);
}

// 将时间戳转换为可读的字符串格式
void print_readable_time(uint32_t timestamp) {
    time_t rawtime = (time_t)timestamp;
    struct tm * timeinfo;
    char buffer[80];

    timeinfo = localtime(&rawtime);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);

    printf("time_stamp: %s\n", buffer);
}

// 回调函数定义
void packet_analysis_callback(const RTPS_PacketInfo *pInfo, const unsigned char *packet_data, int packet_len) {
    // 复制 pInfo 到 npga_info.packet_info
    npga_info.packet_info.timeStamp = pInfo->timeStamp;
	npga_info.packet_info.srcAddress = pInfo->srcAddress;
	npga_info.packet_info.dstAddress = pInfo->dstAddress;
	npga_info.packet_info.srcPort = pInfo->srcPort;
	npga_info.packet_info.dstPort = pInfo->dstPort;
    // 为新的数据包分配内存
    npga_info.packet_data = (unsigned char*)malloc(packet_len);
    if (npga_info.packet_data == NULL) {
        // 内存分配失败，处理错误
        printf("Memory allocation failed!\n");
        return;
    }
    // 复制数据到 npga_info
    memcpy(npga_info.packet_data, packet_data, packet_len);
    npga_info.packet_len = packet_len;

    // 缓冲区用于存储IP地址字符串
    char src_addr[INET_ADDRSTRLEN];
    char dst_addr[INET_ADDRSTRLEN];
	print_readable_time(npga_info.packet_info.timeStamp);
    // 转换并打印IP地址
    uint32_to_ip(npga_info.packet_info.srcAddress, src_addr, sizeof(src_addr));
    uint32_to_ip(npga_info.packet_info.dstAddress, dst_addr, sizeof(dst_addr));
    printf("src_addr: %s\n", src_addr);
    printf("src_port: %u\n", npga_info.packet_info.srcPort);
    printf("dst_addr: %s\n", dst_addr);
    printf("dst_port: %u\n", npga_info.packet_info.dstPort);
    // 打印 packet_data 的内容
    printf("packet_len:%d\n", npga_info.packet_len);

    printf("packet_data: ");
    for (int i = 0; i < npga_info.packet_len; i++) {
        printf("%02x ", npga_info.packet_data[i]);
    }
    printf("\n============================================RTPS\n");
}

// 回调函数定义
void packet_udp_callback(const UDP_PacketInfo *pInfo, const unsigned char *packet_data, int packet_len) {
    // 复制 pInfo 到 npga_info.packet_info
    npga_info.packet_info.timeStamp = pInfo->timeStamp;
	npga_info.packet_info.srcAddress = pInfo->srcAddress;
	npga_info.packet_info.dstAddress = pInfo->dstAddress;
	npga_info.packet_info.srcPort = pInfo->srcPort;
	npga_info.packet_info.dstPort = pInfo->dstPort;
    // 为新的数据包分配内存
    npga_info.packet_data = (unsigned char*)malloc(packet_len);
    if (npga_info.packet_data == NULL) {
        // 内存分配失败，处理错误
        printf("Memory allocation failed!\n");
        return;
    }
    // 复制数据到 npga_info
    memcpy(npga_info.packet_data, packet_data, packet_len);
    npga_info.packet_len = packet_len;

    // 缓冲区用于存储IP地址字符串
    char src_addr[INET_ADDRSTRLEN];
    char dst_addr[INET_ADDRSTRLEN];
	print_readable_time(npga_info.packet_info.timeStamp);
    // 转换并打印IP地址
    uint32_to_ip(npga_info.packet_info.srcAddress, src_addr, sizeof(src_addr));
    uint32_to_ip(npga_info.packet_info.dstAddress, dst_addr, sizeof(dst_addr));
    printf("src_addr: %s\n", src_addr);
    printf("src_port: %u\n", npga_info.packet_info.srcPort);
    printf("dst_addr: %s\n", dst_addr);
    printf("dst_port: %u\n", npga_info.packet_info.dstPort);
    // 打印 packet_data 的内容
    printf("packet_len:%d\n", npga_info.packet_len);

    printf("packet_data: ");
    for (int i = 0; i < npga_info.packet_len; i++) {
        printf("%02x ", npga_info.packet_data[i]);
    }
    printf("\n============================================UDP\n");
}

// 获取 NPGA_PacketInfo 的函数
NPGA_PacketInfo* npga_getPacketInfo() {
    return &npga_info;
}

// 捕获线程函数
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
	

	//// 设置端口
 //   if (npga_setPort("/Device/NPF_{6BF06E61-3D5C-4616-9006-A6E9E87B2DE6}") != 0) {
 //       fprintf(stderr, "Failed to set port\n");
 //       npga_delete();
 //       return -1;
 //   }

	//

 //   // 获取端口
 //   char *port = npga_getPort();
 //   if (port) {
 //       printf("Port: %s\n", port);
 //   } else {
 //       fprintf(stderr, "Port not set\n");
 //   }

	

	 ////设置解析路径
  //  if (npga_setFilePort("D:/capturedFiles/FastDDS_Selftest_RTPD_Data.pcapng") != 0) {
  //      fprintf(stderr, "Failed to set parse pcap file\n");
  //      npga_delete();
  //      return -1;
  //  }

	

	// 设置存储路径和前缀
    if (npga_setPcapPrefix("D:/capturedFiles", "prefix") != 0) {
        fprintf(stderr, "Failed to set pcap prefix\n");
        npga_delete();
        return -1;
    }
	
    // 设置存储时间间隔
    if (npga_setPcapInterval(30) != 0) {
        fprintf(stderr, "Failed to set pcap interval\n");
        npga_delete();
        return -1;
    }
	
    // 获取存储时间间隔
    int interval = npga_getPcapInterval();
    printf("Pcap interval: %d seconds\n", interval);
	
	// 设置过滤规则
    if (npga_setFilter("udp port 8080") != 0) {
        fprintf(stderr, "Failed to set filter\n");
        npga_delete();
        return -1;
    }
	 
    // 获取过滤规则
    char *filter = npga_getFilter();
    if (filter) {
        printf("Filter: %s\n", filter);
    } else {
        fprintf(stderr, "Filter not set\n");
    }

	//// 打印确认
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

	// 设置回调函数
    npga_setCallBack(packet_analysis_callback, 1);
	npga_setUDPCallBack(packet_udp_callback, 1);


	// 获取 NPGA_PacketInfo
    NPGA_PacketInfo *npga_info = npga_getPacketInfo();

    // 创建捕获线程
    HANDLE capture_thread = NULL;
    int thread_created = 0;

    // 控制台输入控制
    char command;
    printf("Enter 's' to start, 'p' to pause, 'r' to resume, 'e' to stop:\n");
    while (1) {
        command = getchar(); // 获取用户输入
        if (command == 's') {
            // 启动捕获会话
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
            // 暂停
            npga_pause();
            printf("Capture session paused\n");
        } else if (command == 'r') {
            // 恢复
            npga_resume();
            printf("Capture session resumed\n");
        } else if (command == 'e') {
            // 停止
            npga_stop();
            printf("Capture session stopped\n");
            break;
        }
        // 清除输入缓冲区
        while (getchar() != '\n');
    }

    // 等待捕获线程结束
    if (thread_created) {
        WaitForSingleObject(capture_thread, INFINITE);
        CloseHandle(capture_thread);
    }

	npga_delete();
	system("PAUSE"); 
	return 0;
}