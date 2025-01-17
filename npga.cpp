#define NPGALIB_EXPORTS
#include "npga.h" //���е�winsock2.h����windows.h��Ҫ������֮ǰ
#include "nshark.h"
#include "ntap.h"

#include <stdio.h>

#define WIRESHARK_DLL_PATH _T("libwiredeal.dll")
#define WIRETAP_DLL_PATH _T("wiretap-1.8.0.dll")

#define MAX_PACKETS 10000
#define DATA_LEN 65535

// δ֪��������
#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xFFFFFFFF
#endif

struct rate_limit_entry npga_rate_limit[MAX_ENTRIES];  // ʹ���µĽṹ����
int npga_entry_count = 0;

// ��ȡ��ǰϵͳʱ�䲢ת��Ϊʱ������뼶��
uint32_t get_current_time_secs() {
  time_t current_time;
  time(&current_time);
  return (uint32_t)current_time;
}

// ���洢���Ļ�����
typedef struct {
  struct pcap_pkthdr header;
  u_char data[DATA_LEN];
} PacketBuffer;

PacketBuffer *captured_packets = NULL;
int num_captured_packets = 0; // ������

// ��̬��������
HINSTANCE hDLL = NULL;
HINSTANCE wiretapDLL = NULL;
BOOL ret = FALSE;
BOOL wiretapRet = FALSE;

static NpgaInstance *npga_instance = NULL;

// ��IP��ַ�ַ���ת��Ϊuint32_t
uint32_t ip_to_uint32(const char *ip) {
  struct in_addr addr;
  inet_pton(AF_INET, ip, &addr);
  return addr.s_addr;
}

//// ��uint32_t���͵�IP��ַת��Ϊ�ַ�����ʽ��IP��ַ
// void uint32_to_ip(uint32_t ip_address, char* buffer, size_t buffer_size) {
//     struct in_addr addr;
//     addr.s_addr = ip_address;
//     inet_ntop(AF_INET, &addr, buffer, buffer_size);
// }

// ��ʼ�� RTPS_PacketInfo �ṹ��Ϊ��
void initializeRTPSPacketInfo(RTPS_PacketInfo *packetInfo) {
  if (packetInfo) {
    packetInfo->timeStamp = 0;
    packetInfo->srcAddress = 0;
    packetInfo->dstAddress = 0;
    packetInfo->srcPort = 0;
    packetInfo->dstPort = 0;
  }
}

// // ��ӡ���
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

// ��ӡ���������
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

    // ��������ֵ
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

// ����
void try_dissect(const u_char *packet_data, const struct pcap_pkthdr *phdr) {
  // ����ǰ�������
  initializeRTPSPacketInfo(npga_instance->packet_info);
  npga_instance->packet_data = NULL;
  npga_instance->packet_len = 0;
  static int frame_number = 1; // ��̬���������ڸ���֡���
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

  // ����ʱ������뼶��
  // ����ʱ���
  fdata->abs_ts.secs = phdr->ts.tv_sec;
  fdata->abs_ts.nsecs = phdr->ts.tv_usec * 1000;

  edt = ws_epan_dissect_new(TRUE, TRUE);
  ws_epan_dissect_run(edt, &pseudo_header, packet_data, fdata, NULL);
  // print_tree(edt->tree->first_child, 0);
  print_fixed_level(edt->tree->first_child, 0, 0, npga_instance);

  // printf("frame_number:%d\n", fdata->num);

  //// ���������ڴ洢IP��ַ�ַ���
  // char src_addr[INET_ADDRSTRLEN];
  // char dst_addr[INET_ADDRSTRLEN];
  // printf("ʱ���: %u\n", npga_instance->packet_info->timeStamp);
  //// ת������ӡIP��ַ
  // uint32_to_ip(npga_instance->packet_info->srcAddress, src_addr,
  // sizeof(src_addr)); uint32_to_ip(npga_instance->packet_info->dstAddress,
  // dst_addr, sizeof(dst_addr)); printf("ԴIP��ַ: %s\n", src_addr);
  // printf("Դ�˿�: %u\n", npga_instance->packet_info->srcPort);
  // printf("Ŀ��IP��ַ: %s\n", dst_addr);
  // printf("Ŀ�Ķ˿�: %u\n", npga_instance->packet_info->dstPort);
  //// ��ӡ packet_data ������
  // printf("���ݰ�����:%d\n", npga_instance->packet_len);
  //
  // printf("���ݰ�: ");
  // for (int i = 0; i < npga_instance->packet_len; i++) {
  //	printf("%02x ", npga_instance->packet_data[i]);
  // }
  // printf("\n============================================\n");

  ws_epan_dissect_free(edt);
  g_free(fdata);
}

// ��ʼ�� Wireshark ��
int init_wireshark() {
  hDLL = LoadWiresharkDLL(WIRESHARK_DLL_PATH);
  if (!hDLL) {
    fprintf(stderr, "nshark�޷�����DLL!\n");
    return 0;
  }

  ret = GetWiresharkFunctions(hDLL);
  if (!ret) {
    fprintf(stderr, "nsharkĳЩ����������ȡʧ�ܣ�\n");
    FreeWiresharkDLL(hDLL);
    return 0;
  }

  wiretapDLL = LoadWiretapDLL(WIRETAP_DLL_PATH);
  if (!wiretapDLL) {
    fprintf(stderr, "wiretap�޷�����DLL!\n");
    return 0;
  }

  wiretapRet = GetWiretapFunctions(wiretapDLL);
  if (!wiretapRet) {
    fprintf(stderr, "wiretapĳЩ����������ȡʧ�ܣ�\n");
    FreeWiresharkDLL(wiretapDLL);
    return 0;
  }

  ws_epan_init(ws_register_all_protocols, ws_register_all_protocol_handoffs,
               NULL, NULL, NULL, NULL, NULL);
  ws_init_dissection();
  return 1;
}

// �� PCAP �ļ�����
void parse_pcap_file(const char *pcap_filename) {
  wtap *wth;
  int err;
  gchar *err_info = NULL;
  gint64 data_offset = 0;
  const struct wtap_pkthdr *phdr;
  struct pcap_pkthdr pcap_header;
  const u_char *packet_data;
  int framenum = 0;

  // ���ļ�
  wth = ws_wtap_open_offline(pcap_filename, &err, &err_info, TRUE);
  if (wth == NULL) {
    fprintf(stderr, "Error opening file %s: %s\n", pcap_filename,
            err_info ? err_info : "Unknown error");
    return;
  }
  fprintf(stderr, "Opened file %s successfully.\n", pcap_filename);

  // ѭ����ȡ������ÿ�����ݰ�
  while (ws_wtap_read(wth, &err, &err_info, &data_offset)) {
    framenum++;
    // ��ȡͷ��Ϣ
    phdr = ws_wtap_phdr(wth);
    // �� wtap_pkthdr ת��Ϊ pcap_pkthdr
    pcap_header.ts.tv_sec = phdr->ts.secs;
    pcap_header.ts.tv_usec = phdr->ts.nsecs / 1000;
    pcap_header.caplen = phdr->caplen;
    pcap_header.len = phdr->len;
    // ��ȡ������
    packet_data = ws_wtap_buf_ptr(wth);
    // ʹ�� try_dissect �����������ݰ�
    try_dissect(packet_data, &pcap_header);
  }

  if (err != 0) {
    fprintf(stderr, "Error reading file %s: %s\n", pcap_filename,
            err_info ? err_info : "Unknown error");
  } else {
    fprintf(stderr, "Finished reading file %s, total frames: %d\n",
            pcap_filename, framenum);
  }

  // �ر� PCAP �ļ�
  ws_wtap_close(wth);
}

// npga_��ȡ����ӿ��б�
char *npga_get_devs() {
  pcap_if_t *alldevs;
  pcap_if_t *d;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *result;
  size_t result_size = 1024;
  size_t offset = 0;

  // �����ʼ�ڴ�
  result = (char *)malloc(result_size);
  if (result == NULL) {
    fprintf(stderr, "Memory allocation error\n");
    return NULL;
  }
  result[0] = '\0';

  // ��ȡ��������ӿ�
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    _snprintf(result, result_size, "Error in pcap_findalldevs: %s\n", errbuf);
    return result;
  }

  // �����ӿ��б���ÿ���ӿڵ����ƺ�������ӵ��ַ�����
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

  // ��ӷָ���
  offset += _snprintf(result + offset, result_size - offset, 
      "\n=== Rate Limit Configuration ===\n");

  // �������ļ���ȡ����ӵ�result
  FILE *fp;
  char line[256];
  unsigned int ip1, ip2, ip3, ip4;
  uint16_t length;
  int rate, truncate_len;
  
  fp = fopen("config/npga-filter.ini", "r");
  if (fp != NULL) {
    while (fgets(line, sizeof(line), fp)) {
        // ����ע���кͿ���
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        // ����ÿ�е�����
        if (sscanf(line, "%u.%u.%u.%u %hu %d %d", 
                    &ip1, &ip2, &ip3, &ip4, &length, &rate, &truncate_len) == 7) {
            
            // ������Ҫ�Ŀռ䲢ȷ�����㹻�ռ�
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

            // ��ӵ�����ַ���
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

  // �ͷŷ������Դ
  pcap_freealldevs(alldevs);
  return result;
}

// ��ȡ�����ļ�
static void init_rate_limits_from_config(void) {
    FILE *fp;
    char line[256];
    unsigned int ip1, ip2, ip3, ip4;
    uint16_t length;
    int rate, truncate_len;
    uint32_t ip;
    
    // �������ļ�
    fp = fopen("config/npga-filter.ini", "r");
    if (fp == NULL) {
        printf("****************Cannot open config/npga-filter.ini************************\n");
        return;
    }
    
    // ��ȡÿһ��
    while (fgets(line, sizeof(line), fp)) {
        // ����ע���кͿ���
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        // ����ÿ�е�IP��ַ�����ȡ��������ƺͽضϳ���
        if (sscanf(line, "%u.%u.%u.%u %hu %d %d", 
                   &ip1, &ip2, &ip3, &ip4, &length, &rate, &truncate_len) == 7) {
            // ת��IP��ַΪ32λ����
            ip = (ip1 << 24) | (ip2 << 16) | (ip3 << 8) | ip4;
			
			printf("Parsed values:\n");
            printf("==>ԴIP: %u.%u.%u.%u\n", ip1, ip2, ip3, ip4);
            printf("==>δ������: %u bytes\n", length);
            printf("==>��������: %d packets/sec\n", rate);
            printf("==>ʵ�����ȡ: %d bytes\n", truncate_len);

            // ��ӵ�rate limit��
            ws_npga_init_rate_entry(ip, length, rate, truncate_len);
        }
    }

    fclose(fp);
}

// npga_��ʼ��
int npga_new(const char *interface) {
  if (!init_wireshark()) {
    return 1;
  }

  ws_npga_init_index_table();
  init_rate_limits_from_config();

  if (npga_instance == NULL) {
    npga_instance = (NpgaInstance *)malloc(sizeof(NpgaInstance));
    npga_instance->id = 1;           // ����IDΪ1
    npga_instance->interface = NULL; // ��ʼ��interfaceΪNULL
    npga_instance->parseFile = NULL; // ��ʼ������·��ΪNULL
    npga_instance->path = NULL;      // ��ʼ��pathΪNULL
    npga_instance->prefix = NULL;    // ��ʼ��prefixΪNULL
    npga_instance->interval = 0;     // ��ʼ��intervalΪ0
    npga_instance->filter = NULL;    // ��ʼ��filterΪNULL
    npga_instance->is_running = 0;
    npga_instance->is_paused = 0;
    npga_instance->pcap_handle = NULL;
    npga_instance->pcap_dumper = NULL;

    // ���䲢��ʼ�� RTPS_PacketInfo �ṹ��
    npga_instance->packet_info =
        (RTPS_PacketInfo *)malloc(sizeof(RTPS_PacketInfo));
    if (npga_instance->packet_info == NULL) {
      free(npga_instance);
      npga_instance = NULL;
      return 1; // �ڴ����ʧ��
    }
    initializeRTPSPacketInfo(npga_instance->packet_info);
    npga_instance->packet_data = NULL;
    npga_instance->packet_len = 0;
    if (npga_instance == NULL || !interface) {
      return -1; // ���ش������
    }

    // �ͷ�֮ǰ��interface�ַ���
    if (npga_instance->interface) {
      free(npga_instance->interface);
    }

    // �������ַ�������������
    npga_instance->interface = strdup(interface);
    if (npga_instance->interface == NULL) {
      return -1; // ���ش������
    }

    // Ϊ captured_packets �����ڴ�
    captured_packets =
        (PacketBuffer *)malloc(sizeof(PacketBuffer) * MAX_PACKETS);
    if (captured_packets == NULL) {
      // �����ڴ����ʧ��
      free(npga_instance->packet_info);
      free(npga_instance);
      npga_instance = NULL;
      return 1;
    }

    return 0;
  }

  
  return 1;
}

// npga_����
void npga_delete() {
  if (npga_instance) {
    if (npga_instance->interface) {
      free(npga_instance->interface); // �ͷ�interface�ַ���
    }
    if (npga_instance->parseFile) {
      free(npga_instance->parseFile); // �ͷŽ���·���ַ���
    }
    if (npga_instance->path) {
      free(npga_instance->path); // �ͷ�path�ַ���
    }
    if (npga_instance->prefix) {
      free(npga_instance->prefix); // �ͷ�prefix�ַ���
    }

    // �ͷ� captured_packets
    if (captured_packets) {
      free(captured_packets);
      captured_packets = NULL;
    }

    free(npga_instance);
  }
}

//// npga_���ö˿�
// int npga_setPort( const char *interface) {
//     if (npga_instance == NULL || !interface) {
//         return -1; // ���ش������
//     }
//
//     // �ͷ�֮ǰ��interface�ַ���
//     if (npga_instance->interface) {
//         free(npga_instance->interface);
//     }
//
//     // �������ַ�������������
//     npga_instance->interface = strdup(interface);
//     if (npga_instance->interface == NULL) {
//         return -1; // ���ش������
//     }
//
//     return 0; // �ɹ�
// }
//
//// npga_��ȡ�˿�
// char* npga_getPort() {
//     if (!npga_instance || !npga_instance->interface) {
//         return NULL; // ����NULL��ʾû�����ýӿ�
//     }
//
//     return npga_instance->interface;
// }

// npga_���ý����ļ�·��
int npga_setFilePort(const char *parseFile) {
  if (!npga_instance || !parseFile) {
    return -1; // ���ش������
  }

  // �ͷ�֮ǰ��pcapfile�ַ���
  if (npga_instance->parseFile) {
    free(npga_instance->parseFile);
  }

  // �������ַ�������������
  npga_instance->parseFile = strdup(parseFile);
  if (!npga_instance->parseFile) {
    return -1; // ���ش������
  }

  return 0; // �ɹ�
}

// npga_���ñ����ļ�·��
int npga_setPcapPrefix(const char *path, const char *prefix) {
  if (!npga_instance || !path || !prefix) {
    return -1; // ���ش������
  }

  // �ͷ�֮ǰ��path��prefix�ַ���
  if (npga_instance->path) {
    free(npga_instance->path);
  }
  if (npga_instance->prefix) {
    free(npga_instance->prefix);
  }

  // �������ַ�������������
  npga_instance->path = strdup(path);
  npga_instance->prefix = strdup(prefix);
  if (!npga_instance->path || !npga_instance->prefix) {
    return -1; // ���ش������
  }

  return 0; // �ɹ�
}

// npga_���ñ���ʱ����
int npga_setPcapInterval(int interval) {
  if (!npga_instance) {
    return -1; // ���ش������
  }

  npga_instance->interval = interval;
  return 0; // �ɹ�
}

// npga_��ȡ����ʱ����
int npga_getPcapInterval() {
  if (!npga_instance) {
    return -1; // ���ش������
  }

  return npga_instance->interval;
}

// npga_���ù��˹���
int npga_setFilter(const char *filter) {
  if (!npga_instance || !filter) {
    return -1; // ���ش������
  }

  // �ͷ�֮ǰ��filter�ַ���
  if (npga_instance->filter) {
    free(npga_instance->filter);
  }

  // �������ַ�������������
  npga_instance->filter = strdup(filter);
  if (!npga_instance->filter) {
    return -1; // ���ش������
  }

  return 0; // �ɹ�
}

// npga_��ȡ���˹���
char *npga_getFilter() {
  if (!npga_instance || !npga_instance->filter) {
    return NULL; // ����NULL��ʾû�����ù��˹���
  }

  return npga_instance->filter;
}

// �����ļ���
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

// ������д���ļ�
void write_buffer_to_file() {
  // ���ȼ���Ƿ���Ҫд��
  if (npga_instance->interval <= 0 || num_captured_packets == 0) {
    return;
  }

  // �����µ��ļ���
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
  num_captured_packets = 0; // ��ջ�����
}

// ���뻺����
void process_packet(u_char *user_data, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet_data) {
  // ����Ƿ�ﵽ�������������
  if (num_captured_packets >= MAX_PACKETS) {
    write_buffer_to_file();   // д���ļ�
    num_captured_packets = 0; // ���ü�����
  }
  memcpy(&captured_packets[num_captured_packets].header, pkthdr,
         sizeof(struct pcap_pkthdr));
  memcpy(captured_packets[num_captured_packets].data, packet_data,
         pkthdr->caplen);
  num_captured_packets++;
}



// ����
void capture_packets() {
  struct pcap_pkthdr header;
  const u_char *packet_data;
  time_t start_time = time(NULL);
  time_t current_time;

  struct bpf_program fp;

  // ������˹���
  if (pcap_compile(npga_instance->pcap_handle, &fp, npga_instance->filter, 0,
                   PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "Error compiling filter: %s\n",
            pcap_geterr(npga_instance->pcap_handle));
    return;
  }

  // ���ù��˹���
  if (pcap_setfilter(npga_instance->pcap_handle, &fp) == -1) {
    fprintf(stderr, "Error setting filter: %s\n",
            pcap_geterr(npga_instance->pcap_handle));
    pcap_freecode(&fp);
    return;
  }

  pcap_freecode(&fp); // �ͷŹ��˹���

  while (npga_instance->is_running) {
    if (npga_instance->is_paused) {
      continue; // �����ͣ������������
    }

    packet_data = pcap_next(npga_instance->pcap_handle, &header);

    if (packet_data != NULL) {
      process_packet(NULL, &header, packet_data);
      // ����
      try_dissect(packet_data, &header);
      
      // ���ʱ����
      if (npga_instance->interval > 0) {
        current_time = time(NULL);
        if (difftime(current_time, start_time) >= npga_instance->interval) {
          write_buffer_to_file();  // д�뵱ǰ����������
          num_captured_packets = 0;  // ���ü�����
          start_time = current_time;  // ���¿�ʼʱ��
        }
      }
    }
    
  }
  if (npga_instance->interval > 0) {
    write_buffer_to_file(); // ��ֹͣ�����д��ʣ������
  }
  pcap_close(npga_instance->pcap_handle);
  npga_instance->is_running = 0;
}

// npga_��������
int npga_start() {
  if (!npga_instance || !npga_instance->interface || !npga_instance->path ||
      !npga_instance->prefix) {
    return -1; // ���ش������
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

  return 0; // �ɹ�
}

// npga_ֹͣ
int npga_stop() {
  if (!npga_instance || !npga_instance->is_running) {
    return -1; // ���ش������
  }

  npga_instance->is_running = 0;
  return 0;
}

// npga_��ͣ,���˹�������Ϊ0����ֹ��������
int npga_pause() {
  if (!npga_instance || !npga_instance->is_running) {
    return -1; // ���ش������
  }

  npga_instance->is_paused = 1;

  // ���ù��˹���Ϊ0
  const char *filter_exp = "ip[0] = 0";
  struct bpf_program fp;
  // ������˹���
  if (pcap_compile(npga_instance->pcap_handle, &fp, filter_exp, 0,
                   PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "Error compiling filter: %s\n",
            pcap_geterr(npga_instance->pcap_handle));
  }
  // ���ù��˹���
  if (pcap_setfilter(npga_instance->pcap_handle, &fp) == -1) {
    fprintf(stderr, "Error setting filter: %s\n",
            pcap_geterr(npga_instance->pcap_handle));
    pcap_freecode(&fp);
  }
  pcap_freecode(&fp); // �ͷŹ��˹���

  return 0;
}

// npga_�ָ�
int npga_resume() {
  if (!npga_instance || !npga_instance->is_running) {
    return -1; // ���ش������
  }

  npga_instance->is_paused = 0;

  struct bpf_program fp;

  // ������˹���
  if (pcap_compile(npga_instance->pcap_handle, &fp, npga_instance->filter, 0,
                   PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "Error compiling filter: %s\n",
            pcap_geterr(npga_instance->pcap_handle));
  }
  // ���ù��˹���
  if (pcap_setfilter(npga_instance->pcap_handle, &fp) == -1) {
    fprintf(stderr, "Error setting filter: %s\n",
            pcap_geterr(npga_instance->pcap_handle));
    pcap_freecode(&fp);
  }
  pcap_freecode(&fp); // �ͷŹ��˹���

  return 0;
}

// npga_���ûص�����
void npga_setCallBack(RTPSPacketAnalysisCallback callback, int type) {
  ws_setRTPS2DataCallback(callback, type);
}

void npga_setUDPCallBack(UDPPacketAnalysisCallback callback, int type) {
  ws_setUDPDataCallback(callback, type);
}
