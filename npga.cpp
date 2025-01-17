#define NPGALIB_EXPORTS
#include "npga.h" //其中的winsock2.h包含windows.h，要放在这之前
#include "nshark.h"
#include "ntap.h"

#include <stdio.h>

#define WIRESHARK_DLL_PATH _T("libwiredeal.dll")
#define WIRETAP_DLL_PATH _T("wiretap-1.8.0.dll")

#define MAX_PACKETS 10000
#define DATA_LEN 65535

// 未知网络掩码
#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xFFFFFFFF
#endif

struct rate_limit_entry npga_rate_limit[MAX_ENTRIES];  // 使用新的结构体名
int npga_entry_count = 0;

// 获取当前系统时间并转换为时间戳（秒级）
uint32_t get_current_time_secs() {
  time_t current_time;
  time(&current_time);
  return (uint32_t)current_time;
}

// 包存储到的缓冲区
typedef struct {
  struct pcap_pkthdr header;
  u_char data[DATA_LEN];
} PacketBuffer;

PacketBuffer *captured_packets = NULL;
int num_captured_packets = 0; // 计数器

// 动态库加载相关
HINSTANCE hDLL = NULL;
HINSTANCE wiretapDLL = NULL;
BOOL ret = FALSE;
BOOL wiretapRet = FALSE;

static NpgaInstance *npga_instance = NULL;

// 将IP地址字符串转换为uint32_t
uint32_t ip_to_uint32(const char *ip) {
  struct in_addr addr;
  inet_pton(AF_INET, ip, &addr);
  return addr.s_addr;
}

//// 将uint32_t类型的IP地址转换为字符串形式的IP地址
// void uint32_to_ip(uint32_t ip_address, char* buffer, size_t buffer_size) {
//     struct in_addr addr;
//     addr.s_addr = ip_address;
//     inet_ntop(AF_INET, &addr, buffer, buffer_size);
// }

// 初始化 RTPS_PacketInfo 结构体为空
void initializeRTPSPacketInfo(RTPS_PacketInfo *packetInfo) {
  if (packetInfo) {
    packetInfo->timeStamp = 0;
    packetInfo->srcAddress = 0;
    packetInfo->dstAddress = 0;
    packetInfo->srcPort = 0;
    packetInfo->dstPort = 0;
  }
}

// // 打印输出
// void print_tree(proto_tree* tree, int level)
// {
//     if(tree == NULL)
//         return;

//     for(int i=0; i<level; ++i)
//         printf("    ");

//     gchar field_str[ITEM_LABEL_LENGTH + 1] = {0};
//     if(tree->finfo->rep == NULL)
//         ws_proto_item_fill_label(tree->finfo, field_str);
//     else
//         strcpy_s(field_str, tree->finfo->rep->representation);

//     if(!PROTO_ITEM_IS_HIDDEN(tree))
//         printf("%s\n", field_str);

//     print_tree(tree->first_child, level+1);
//     print_tree(tree->next, level);

// }

// 打印输出并解析
void print_fixed_level(proto_tree *tree, int current_level, int target_level,
                       NpgaInstance *npga_instance) {
  if (tree == NULL)
    return;

  if (current_level == target_level) {
    // for(int i=0; i<current_level; ++i)
    //     printf("    ");

    gchar field_str[ITEM_LABEL_LENGTH + 1] = {0};
    if (tree->finfo->rep == NULL)
      ws_proto_item_fill_label(tree->finfo, field_str);
    else
      strcpy_s(field_str, tree->finfo->rep->representation);

    // if(!PROTO_ITEM_IS_HIDDEN(tree))
    //     printf("%s\n", field_str);

    // 解析并赋值
    if (strstr(field_str, "Src: ") &&
        strstr(field_str, "Internet Protocol Version 4")) {
      const char *src_ip_start = strstr(field_str, "Src: ") + 5;
      const char *src_ip_end = strchr(src_ip_start, ' ');
      char src_ip[16] = {0};
      strncpy(src_ip, src_ip_start, src_ip_end - src_ip_start);
      npga_instance->packet_info->srcAddress = ip_to_uint32(src_ip);
    }
    if (strstr(field_str, "Dst: ") &&
        strstr(field_str, "Internet Protocol Version 4")) {
      const char *dst_ip_start = strstr(field_str, "Dst: ") + 5;
      const char *dst_ip_end = strchr(dst_ip_start, ' ');
      char dst_ip[16] = {0};
      strncpy(dst_ip, dst_ip_start, dst_ip_end - dst_ip_start);
      npga_instance->packet_info->dstAddress = ip_to_uint32(dst_ip);
    }
    if (strstr(field_str, "Src Port: ")) {
      const char *src_port_start = strstr(field_str, "Src Port: ") + 10;
      npga_instance->packet_info->srcPort = atoi(src_port_start);
    }
    if (strstr(field_str, "Dst Port: ")) {
      const char *dst_port_start = strstr(field_str, "Dst Port: ") + 10;
      npga_instance->packet_info->dstPort = atoi(dst_port_start);
    }
  }

  if (current_level < target_level) {
    print_fixed_level(tree->first_child, current_level + 1, target_level,
                      npga_instance);
  }

  print_fixed_level(tree->next, current_level, target_level, npga_instance);
}

// 解析
void try_dissect(const u_char *packet_data, const struct pcap_pkthdr *phdr) {
  // 解析前清空内容
  initializeRTPSPacketInfo(npga_instance->packet_info);
  npga_instance->packet_data = NULL;
  npga_instance->packet_len = 0;
  static int frame_number = 1; // 静态变量，用于跟踪帧编号
  frame_data *fdata;
  epan_dissect_t *edt;
  union wtap_pseudo_header pseudo_header;
  pseudo_header.eth.fcs_len = -1;

  fdata = (frame_data *)g_new(frame_data, 1);

  memset(fdata, 0, sizeof(frame_data));
  fdata->pfd = NULL;
  fdata->num = frame_number++;
  fdata->interface_id = 0;
  fdata->pkt_len = phdr->len;
  fdata->cap_len = phdr->caplen;
  fdata->cum_bytes = 0;
  fdata->file_off = 0;
  fdata->subnum = 0;
  fdata->lnk_t = WTAP_ENCAP_ETHERNET;
  fdata->flags.encoding = 0; // PACKET_CHAR_ENC_CHAR_ASCII;
  fdata->flags.visited = 0;
  fdata->flags.marked = 0;
  fdata->flags.ref_time = 0;
  fdata->color_filter = NULL;
  fdata->opt_comment = NULL;

  // 设置时间戳（秒级）
  // 设置时间戳
  fdata->abs_ts.secs = phdr->ts.tv_sec;
  fdata->abs_ts.nsecs = phdr->ts.tv_usec * 1000;

  edt = ws_epan_dissect_new(TRUE, TRUE);
  ws_epan_dissect_run(edt, &pseudo_header, packet_data, fdata, NULL);
  // print_tree(edt->tree->first_child, 0);
  print_fixed_level(edt->tree->first_child, 0, 0, npga_instance);

  // printf("frame_number:%d\n", fdata->num);

  //// 缓冲区用于存储IP地址字符串
  // char src_addr[INET_ADDRSTRLEN];
  // char dst_addr[INET_ADDRSTRLEN];
  // printf("时间戳: %u\n", npga_instance->packet_info->timeStamp);
  //// 转换并打印IP地址
  // uint32_to_ip(npga_instance->packet_info->srcAddress, src_addr,
  // sizeof(src_addr)); uint32_to_ip(npga_instance->packet_info->dstAddress,
  // dst_addr, sizeof(dst_addr)); printf("源IP地址: %s\n", src_addr);
  // printf("源端口: %u\n", npga_instance->packet_info->srcPort);
  // printf("目的IP地址: %s\n", dst_addr);
  // printf("目的端口: %u\n", npga_instance->packet_info->dstPort);
  //// 打印 packet_data 的内容
  // printf("数据包长度:%d\n", npga_instance->packet_len);
  //
  // printf("数据包: ");
  // for (int i = 0; i < npga_instance->packet_len; i++) {
  //	printf("%02x ", npga_instance->packet_data[i]);
  // }
  // printf("\n============================================\n");

  ws_epan_dissect_free(edt);
  g_free(fdata);
}

// 初始化 Wireshark 库
int init_wireshark() {
  hDLL = LoadWiresharkDLL(WIRESHARK_DLL_PATH);
  if (!hDLL) {
    fprintf(stderr, "nshark无法加载DLL!\n");
    return 0;
  }

  ret = GetWiresharkFunctions(hDLL);
  if (!ret) {
    fprintf(stderr, "nshark某些导出函数获取失败！\n");
    FreeWiresharkDLL(hDLL);
    return 0;
  }

  wiretapDLL = LoadWiretapDLL(WIRETAP_DLL_PATH);
  if (!wiretapDLL) {
    fprintf(stderr, "wiretap无法加载DLL!\n");
    return 0;
  }

  wiretapRet = GetWiretapFunctions(wiretapDLL);
  if (!wiretapRet) {
    fprintf(stderr, "wiretap某些导出函数获取失败！\n");
    FreeWiresharkDLL(wiretapDLL);
    return 0;
  }

  ws_epan_init(ws_register_all_protocols, ws_register_all_protocol_handoffs,
               NULL, NULL, NULL, NULL, NULL);
  ws_init_dissection();
  return 1;
}

// 从 PCAP 文件解析
void parse_pcap_file(const char *pcap_filename) {
  wtap *wth;
  int err;
  gchar *err_info = NULL;
  gint64 data_offset = 0;
  const struct wtap_pkthdr *phdr;
  struct pcap_pkthdr pcap_header;
  const u_char *packet_data;
  int framenum = 0;

  // 打开文件
  wth = ws_wtap_open_offline(pcap_filename, &err, &err_info, TRUE);
  if (wth == NULL) {
    fprintf(stderr, "Error opening file %s: %s\n", pcap_filename,
            err_info ? err_info : "Unknown error");
    return;
  }
  fprintf(stderr, "Opened file %s successfully.\n", pcap_filename);

  // 循环读取并处理每个数据包
  while (ws_wtap_read(wth, &err, &err_info, &data_offset)) {
    framenum++;
    // 获取头信息
    phdr = ws_wtap_phdr(wth);
    // 将 wtap_pkthdr 转换为 pcap_pkthdr
    pcap_header.ts.tv_sec = phdr->ts.secs;
    pcap_header.ts.tv_usec = phdr->ts.nsecs / 1000;
    pcap_header.caplen = phdr->caplen;
    pcap_header.len = phdr->len;
    // 获取包内容
    packet_data = ws_wtap_buf_ptr(wth);
    // 使用 try_dissect 函数处理数据包
    try_dissect(packet_data, &pcap_header);
  }

  if (err != 0) {
    fprintf(stderr, "Error reading file %s: %s\n", pcap_filename,
            err_info ? err_info : "Unknown error");
  } else {
    fprintf(stderr, "Finished reading file %s, total frames: %d\n",
            pcap_filename, framenum);
  }

  // 关闭 PCAP 文件
  ws_wtap_close(wth);
}

// npga_获取网络接口列表
char *npga_get_devs() {
  pcap_if_t *alldevs;
  pcap_if_t *d;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *result;
  size_t result_size = 1024;
  size_t offset = 0;

  // 分配初始内存
  result = (char *)malloc(result_size);
  if (result == NULL) {
    fprintf(stderr, "Memory allocation error\n");
    return NULL;
  }
  result[0] = '\0';

  // 获取所有网络接口
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    _snprintf(result, result_size, "Error in pcap_findalldevs: %s\n", errbuf);
    return result;
  }

  // 遍历接口列表并将每个接口的名称和描述添加到字符串中
  for (d = alldevs; d != NULL; d = d->next) {
    size_t needed_size =
        _snprintf(NULL, 0, "Interface: %s\nDescription: %s\n", d->name,
                  d->description ? d->description
                                 : "No description available") +
        1;
    if (offset + needed_size > result_size) {
      result_size *= 2;
      result = (char *)realloc(result, result_size);
      if (result == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        pcap_freealldevs(alldevs);
        return NULL;
      }
    }
    offset +=
        _snprintf(result + offset, result_size - offset,
                  "Interface: %s\nDescription: %s\n", d->name,
                  d->description ? d->description : "No description available");
  }

  // 添加分隔线
  offset += _snprintf(result + offset, result_size - offset, 
      "\n=== Rate Limit Configuration ===\n");

  // 从配置文件读取并添加到result
  FILE *fp;
  char line[256];
  unsigned int ip1, ip2, ip3, ip4;
  uint16_t length;
  int rate, truncate_len;
  
  fp = fopen("config/npga-filter.ini", "r");
  if (fp != NULL) {
    while (fgets(line, sizeof(line), fp)) {
        // 跳过注释行和空行
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        // 解析每行的配置
        if (sscanf(line, "%u.%u.%u.%u %hu %d %d", 
                    &ip1, &ip2, &ip3, &ip4, &length, &rate, &truncate_len) == 7) {
            
            // 计算需要的空间并确保有足够空间
            size_t needed_size = _snprintf(NULL, 0,
                "Source IP: %u.%u.%u.%u\n"
                "Packet Length: %u bytes\n"
                "Rate Limit: %d packets/sec\n"
                "Truncate Length: %d bytes\n\n",
                ip1, ip2, ip3, ip4,
                length, rate, truncate_len) + 1;

            if (offset + needed_size > result_size) {
                result_size *= 2;
                result = (char *)realloc(result, result_size);
                if (result == NULL) {
                    fprintf(stderr, "Memory allocation error\n");
                    pcap_freealldevs(alldevs);
                    fclose(fp);
                    return NULL;
                }
            }

            // 添加到结果字符串
            offset += _snprintf(result + offset, result_size - offset,
                "Source IP: %u.%u.%u.%u\n"
                "Packet Length: %u bytes\n"
                "Rate Limit: %d packets/sec\n"
                "Truncate Length: %d bytes\n\n",
                ip1, ip2, ip3, ip4,
                length, rate, truncate_len);
        }
    }
    fclose(fp);
  } else {
      offset += _snprintf(result + offset, result_size - offset,
          "Warning: Cannot open config/npga-filter.ini\n");
  }

  // 释放分配的资源
  pcap_freealldevs(alldevs);
  return result;
}

// 读取配置文件
static void init_rate_limits_from_config(void) {
    FILE *fp;
    char line[256];
    unsigned int ip1, ip2, ip3, ip4;
    uint16_t length;
    int rate, truncate_len;
    uint32_t ip;
    
    // 打开配置文件
    fp = fopen("config/npga-filter.ini", "r");
    if (fp == NULL) {
        printf("****************Cannot open config/npga-filter.ini************************\n");
        return;
    }
    
    // 读取每一行
    while (fgets(line, sizeof(line), fp)) {
        // 跳过注释行和空行
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        // 解析每行的IP地址、长度、速率限制和截断长度
        if (sscanf(line, "%u.%u.%u.%u %hu %d %d", 
                   &ip1, &ip2, &ip3, &ip4, &length, &rate, &truncate_len) == 7) {
            // 转换IP地址为32位整数
            ip = (ip1 << 24) | (ip2 << 16) | (ip3 << 8) | ip4;
			
			printf("Parsed values:\n");
            printf("==>源IP: %u.%u.%u.%u\n", ip1, ip2, ip3, ip4);
            printf("==>未处理长度: %u bytes\n", length);
            printf("==>捕获速率: %d packets/sec\n", rate);
            printf("==>实际需截取: %d bytes\n", truncate_len);

            // 添加到rate limit表
            ws_npga_init_rate_entry(ip, length, rate, truncate_len);
        }
    }

    fclose(fp);
}

// npga_初始化
int npga_new(const char *interface) {
  if (!init_wireshark()) {
    return 1;
  }

  ws_npga_init_index_table();
  init_rate_limits_from_config();

  if (npga_instance == NULL) {
    npga_instance = (NpgaInstance *)malloc(sizeof(NpgaInstance));
    npga_instance->id = 1;           // 假设ID为1
    npga_instance->interface = NULL; // 初始化interface为NULL
    npga_instance->parseFile = NULL; // 初始化解析路径为NULL
    npga_instance->path = NULL;      // 初始化path为NULL
    npga_instance->prefix = NULL;    // 初始化prefix为NULL
    npga_instance->interval = 0;     // 初始化interval为0
    npga_instance->filter = NULL;    // 初始化filter为NULL
    npga_instance->is_running = 0;
    npga_instance->is_paused = 0;
    npga_instance->pcap_handle = NULL;
    npga_instance->pcap_dumper = NULL;

    // 分配并初始化 RTPS_PacketInfo 结构体
    npga_instance->packet_info =
        (RTPS_PacketInfo *)malloc(sizeof(RTPS_PacketInfo));
    if (npga_instance->packet_info == NULL) {
      free(npga_instance);
      npga_instance = NULL;
      return 1; // 内存分配失败
    }
    initializeRTPSPacketInfo(npga_instance->packet_info);
    npga_instance->packet_data = NULL;
    npga_instance->packet_len = 0;
    if (npga_instance == NULL || !interface) {
      return -1; // 返回错误代码
    }

    // 释放之前的interface字符串
    if (npga_instance->interface) {
      free(npga_instance->interface);
    }

    // 分配新字符串并复制内容
    npga_instance->interface = strdup(interface);
    if (npga_instance->interface == NULL) {
      return -1; // 返回错误代码
    }

    // 为 captured_packets 分配内存
    captured_packets =
        (PacketBuffer *)malloc(sizeof(PacketBuffer) * MAX_PACKETS);
    if (captured_packets == NULL) {
      // 处理内存分配失败
      free(npga_instance->packet_info);
      free(npga_instance);
      npga_instance = NULL;
      return 1;
    }

    return 0;
  }

  
  return 1;
}

// npga_清理
void npga_delete() {
  if (npga_instance) {
    if (npga_instance->interface) {
      free(npga_instance->interface); // 释放interface字符串
    }
    if (npga_instance->parseFile) {
      free(npga_instance->parseFile); // 释放解析路径字符串
    }
    if (npga_instance->path) {
      free(npga_instance->path); // 释放path字符串
    }
    if (npga_instance->prefix) {
      free(npga_instance->prefix); // 释放prefix字符串
    }

    // 释放 captured_packets
    if (captured_packets) {
      free(captured_packets);
      captured_packets = NULL;
    }

    free(npga_instance);
  }
}

//// npga_设置端口
// int npga_setPort( const char *interface) {
//     if (npga_instance == NULL || !interface) {
//         return -1; // 返回错误代码
//     }
//
//     // 释放之前的interface字符串
//     if (npga_instance->interface) {
//         free(npga_instance->interface);
//     }
//
//     // 分配新字符串并复制内容
//     npga_instance->interface = strdup(interface);
//     if (npga_instance->interface == NULL) {
//         return -1; // 返回错误代码
//     }
//
//     return 0; // 成功
// }
//
//// npga_获取端口
// char* npga_getPort() {
//     if (!npga_instance || !npga_instance->interface) {
//         return NULL; // 返回NULL表示没有设置接口
//     }
//
//     return npga_instance->interface;
// }

// npga_设置解析文件路径
int npga_setFilePort(const char *parseFile) {
  if (!npga_instance || !parseFile) {
    return -1; // 返回错误代码
  }

  // 释放之前的pcapfile字符串
  if (npga_instance->parseFile) {
    free(npga_instance->parseFile);
  }

  // 分配新字符串并复制内容
  npga_instance->parseFile = strdup(parseFile);
  if (!npga_instance->parseFile) {
    return -1; // 返回错误代码
  }

  return 0; // 成功
}

// npga_设置保存文件路径
int npga_setPcapPrefix(const char *path, const char *prefix) {
  if (!npga_instance || !path || !prefix) {
    return -1; // 返回错误代码
  }

  // 释放之前的path和prefix字符串
  if (npga_instance->path) {
    free(npga_instance->path);
  }
  if (npga_instance->prefix) {
    free(npga_instance->prefix);
  }

  // 分配新字符串并复制内容
  npga_instance->path = strdup(path);
  npga_instance->prefix = strdup(prefix);
  if (!npga_instance->path || !npga_instance->prefix) {
    return -1; // 返回错误代码
  }

  return 0; // 成功
}

// npga_设置保存时间间隔
int npga_setPcapInterval(int interval) {
  if (!npga_instance) {
    return -1; // 返回错误代码
  }

  npga_instance->interval = interval;
  return 0; // 成功
}

// npga_获取保存时间间隔
int npga_getPcapInterval() {
  if (!npga_instance) {
    return -1; // 返回错误代码
  }

  return npga_instance->interval;
}

// npga_设置过滤规则
int npga_setFilter(const char *filter) {
  if (!npga_instance || !filter) {
    return -1; // 返回错误代码
  }

  // 释放之前的filter字符串
  if (npga_instance->filter) {
    free(npga_instance->filter);
  }

  // 分配新字符串并复制内容
  npga_instance->filter = strdup(filter);
  if (!npga_instance->filter) {
    return -1; // 返回错误代码
  }

  return 0; // 成功
}

// npga_获取过滤规则
char *npga_getFilter() {
  if (!npga_instance || !npga_instance->filter) {
    return NULL; // 返回NULL表示没有设置过滤规则
  }

  return npga_instance->filter;
}

// 生成文件名
char *generate_filename(const char *path, const char *prefix) {
  time_t rawtime;
  struct tm *timeinfo;
  char buffer[80];

  time(&rawtime);
  timeinfo = localtime(&rawtime);
  strftime(buffer, sizeof(buffer), "%Y%m%d%H%M%S", timeinfo);

  size_t filename_len = strlen(path) + strlen(prefix) + strlen(buffer) +
                        10; // Extra for slashes and extension
  char *filename = (char *)malloc(filename_len);
  if (filename) {
    _snprintf(filename, filename_len, "%s\\%s_%s.pcapng", path, prefix, buffer);
  }
  return filename;
}

// 缓冲区写入文件
void write_buffer_to_file() {
  // 首先检查是否需要写入
  if (npga_instance->interval <= 0 || num_captured_packets == 0) {
    return;
  }

  // 生成新的文件名
  char *filename =
      generate_filename(npga_instance->path, npga_instance->prefix);
  if (!filename) {
    fprintf(stderr, "Error generating filename\n");
    return;
  }

  pcap_dumper_t *pcap_dumper =
      pcap_dump_open(npga_instance->pcap_handle, filename);
  if (!pcap_dumper) {
    fprintf(stderr, "Error opening file for packet dump: %s\n",
            pcap_geterr(npga_instance->pcap_handle));
    free(filename);
    return;
  }

  for (int i = 0; i < num_captured_packets; i++) {
    pcap_dump((u_char *)pcap_dumper, &captured_packets[i].header,
              captured_packets[i].data);
  }

  pcap_dump_close(pcap_dumper);
  free(filename);
  num_captured_packets = 0; // 清空缓冲区
}

// 存入缓冲区
void process_packet(u_char *user_data, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet_data) {
  // 检查是否达到缓冲区最大容量
  if (num_captured_packets >= MAX_PACKETS) {
    write_buffer_to_file();   // 写入文件
    num_captured_packets = 0; // 重置计数器
  }
  memcpy(&captured_packets[num_captured_packets].header, pkthdr,
         sizeof(struct pcap_pkthdr));
  memcpy(captured_packets[num_captured_packets].data, packet_data,
         pkthdr->caplen);
  num_captured_packets++;
}



// 捕获
void capture_packets() {
  struct pcap_pkthdr header;
  const u_char *packet_data;
  time_t start_time = time(NULL);
  time_t current_time;

  struct bpf_program fp;

  // 编译过滤规则
  if (pcap_compile(npga_instance->pcap_handle, &fp, npga_instance->filter, 0,
                   PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "Error compiling filter: %s\n",
            pcap_geterr(npga_instance->pcap_handle));
    return;
  }

  // 设置过滤规则
  if (pcap_setfilter(npga_instance->pcap_handle, &fp) == -1) {
    fprintf(stderr, "Error setting filter: %s\n",
            pcap_geterr(npga_instance->pcap_handle));
    pcap_freecode(&fp);
    return;
  }

  pcap_freecode(&fp); // 释放过滤规则

  while (npga_instance->is_running) {
    if (npga_instance->is_paused) {
      continue; // 如果暂停，则跳过捕获
    }

    packet_data = pcap_next(npga_instance->pcap_handle, &header);

    if (packet_data != NULL) {
      process_packet(NULL, &header, packet_data);
      // 解析
      try_dissect(packet_data, &header);
      
      // 检查时间间隔
      if (npga_instance->interval > 0) {
        current_time = time(NULL);
        if (difftime(current_time, start_time) >= npga_instance->interval) {
          write_buffer_to_file();  // 写入当前缓冲区内容
          num_captured_packets = 0;  // 重置计数器
          start_time = current_time;  // 更新开始时间
        }
      }
    }
    
  }
  if (npga_instance->interval > 0) {
    write_buffer_to_file(); // 在停止捕获后写入剩余数据
  }
  pcap_close(npga_instance->pcap_handle);
  npga_instance->is_running = 0;
}

// npga_开启捕获
int npga_start() {
  if (!npga_instance || !npga_instance->interface || !npga_instance->path ||
      !npga_instance->prefix) {
    return -1; // 返回错误代码
  }

  if (npga_instance->parseFile) {
    parse_pcap_file(npga_instance->parseFile);
    npga_instance->is_running = 0;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  npga_instance->pcap_handle =
      pcap_open_live(npga_instance->interface, 65536, 1, 1000, errbuf);
  if (npga_instance->pcap_handle == NULL) {
    fprintf(stderr, "Error opening PCAP on interface %s: %s\n",
            npga_instance->interface, errbuf);
    return -1;
  }

  npga_instance->is_running = 1;
  npga_instance->is_paused = 0;

  capture_packets();

  return 0; // 成功
}

// npga_停止
int npga_stop() {
  if (!npga_instance || !npga_instance->is_running) {
    return -1; // 返回错误代码
  }

  npga_instance->is_running = 0;
  return 0;
}

// npga_暂停,过滤规则设置为0，防止继续捕获
int npga_pause() {
  if (!npga_instance || !npga_instance->is_running) {
    return -1; // 返回错误代码
  }

  npga_instance->is_paused = 1;

  // 设置过滤规则为0
  const char *filter_exp = "ip[0] = 0";
  struct bpf_program fp;
  // 编译过滤规则
  if (pcap_compile(npga_instance->pcap_handle, &fp, filter_exp, 0,
                   PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "Error compiling filter: %s\n",
            pcap_geterr(npga_instance->pcap_handle));
  }
  // 设置过滤规则
  if (pcap_setfilter(npga_instance->pcap_handle, &fp) == -1) {
    fprintf(stderr, "Error setting filter: %s\n",
            pcap_geterr(npga_instance->pcap_handle));
    pcap_freecode(&fp);
  }
  pcap_freecode(&fp); // 释放过滤规则

  return 0;
}

// npga_恢复
int npga_resume() {
  if (!npga_instance || !npga_instance->is_running) {
    return -1; // 返回错误代码
  }

  npga_instance->is_paused = 0;

  struct bpf_program fp;

  // 编译过滤规则
  if (pcap_compile(npga_instance->pcap_handle, &fp, npga_instance->filter, 0,
                   PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "Error compiling filter: %s\n",
            pcap_geterr(npga_instance->pcap_handle));
  }
  // 设置过滤规则
  if (pcap_setfilter(npga_instance->pcap_handle, &fp) == -1) {
    fprintf(stderr, "Error setting filter: %s\n",
            pcap_geterr(npga_instance->pcap_handle));
    pcap_freecode(&fp);
  }
  pcap_freecode(&fp); // 释放过滤规则

  return 0;
}

// npga_设置回调函数
void npga_setCallBack(RTPSPacketAnalysisCallback callback, int type) {
  ws_setRTPS2DataCallback(callback, type);
}

void npga_setUDPCallBack(UDPPacketAnalysisCallback callback, int type) {
  ws_setUDPDataCallback(callback, type);
}
