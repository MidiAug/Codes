/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif
typedef int bool;
#define bool int

#define false 0
#define true 1

#include <time.h>
#include <pcap.h>
#include <Packet32.h>
#include <ntddndis.h>
#include <time.h>
#include <stdio.h>
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")

u_char user[20];//用户名
u_char pass[20];//密码


/* 4 bytes IP address */
typedef struct tcp_header
{
	u_short sport;//源程序的端口号
	u_short dsport;//目的程序的端口号
	u_int seq;//序列号 SN
	u_int ack_num;//确认号
	u_char ihl; //Internet 头部长度
	u_char frame;
	u_short wsize;//窗口大小
	u_short crc; //check sum
	u_short urg;
}tcp_header;
/* IPv4 首部 */
typedef struct ip_header {
	u_char ver_ihl; // Version (4 bits) +Internet header length (4 bits)
	u_char tos; // Type of service
	u_short tlen; // Total length
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragmentoffset (13 bits)
	u_char ttl; // Time to live
	u_char proto; // Protocol
	u_short crc; // Header checksum
	u_char saddr[4]; // Source address
	u_char daddr[4]; // Destination address
	u_int op_pad; // Option + Padding
} ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;
typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "tcp port 21";
	struct bpf_program fcode;
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	/* Check if the user specified a valid adapter */
	if(inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	if(d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff; 


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	
	return 0;
}



void format_timestamp(const struct timeval* timestamp) {
	struct tm* tm_info;
	char buffer[20]; // 存储时间字符串的缓冲区

	time_t seconds = timestamp->tv_sec; // 获取秒数部分
	tm_info = localtime(&seconds);      // 将秒数转换为本地时间结构体

	// 格式化时间字符串为 "YYYY-MM-DD HH:MM:SS"
	strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);

	// 打印格式化后的时间字符串和微秒数
	printf("Formatted time: %s.%06ld\n", buffer, timestamp->tv_usec);
}

/* Callback function invoked by libpcap for every incoming packet */
void output(ip_header* ih, mac_header* mh, const struct pcap_pkthdr* header, char user[], char pass[], bool isSucceed)
{
	if (user[0] == '\0')
		return;

	char timestr[46];
	struct tm* ltime;
	time_t local_tv_sec;

	/*将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);


	/*
		输出到控制台
	*/
	printf("%s,", timestr);//时间

	// 从登录后 ftp服务器 给客户机返回的信息提取目标地址（FTP服务器地址）和源地址（客户机地址）
	printf("%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->dest_addr[0],
		mh->dest_addr[1],
		mh->dest_addr[2],
		mh->dest_addr[3],
		mh->dest_addr[4],
		mh->dest_addr[5]);//客户机地址
	printf("%d.%d.%d.%d,",
		ih->daddr[0],
		ih->daddr[1],
		ih->daddr[2],
		ih->daddr[3]);//客户机IP

	printf("%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->src_addr[0],
		mh->src_addr[1],
		mh->src_addr[2],
		mh->src_addr[3],
		mh->src_addr[4],
		mh->src_addr[5]);//FTP服务器MAC
	printf("%d.%d.%d.%d,",
		ih->saddr[0],
		ih->saddr[1],
		ih->saddr[2],
		ih->saddr[3]);//FTP服务器IP

	printf("%s,%s,", user, pass);//账号密码

	if (isSucceed) {
		printf("SUCCEED\n");
	}
	else {
		printf("FAILED\n");
	}


	/*
		输出到文件
	*/
	FILE* fp = fopen("AnalyseFTPPacket-log.csv", "a+");
	fprintf(fp, "%s,", timestr);//时间

	fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->dest_addr[0],
		mh->dest_addr[1],
		mh->dest_addr[2],
		mh->dest_addr[3],
		mh->dest_addr[4],
		mh->dest_addr[5]);//客户机地址
	fprintf(fp, "%d.%d.%d.%d,",
		ih->daddr[0],
		ih->daddr[1],
		ih->daddr[2],
		ih->daddr[3]);//客户机IP

	fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->src_addr[0],
		mh->src_addr[1],
		mh->src_addr[2],
		mh->src_addr[3],
		mh->src_addr[4],
		mh->src_addr[5]);//FTP服务器MAC
	fprintf(fp, "%d.%d.%d.%d,",
		ih->saddr[0],
		ih->saddr[1],
		ih->saddr[2],
		ih->saddr[3]);//FTP服务器IP

	fprintf(fp, "%s,%s,", user, pass);//账号密码

	if (isSucceed) {
		fprintf(fp, "SUCCEED\n");
	}
	else {
		fprintf(fp, "FAILED\n");
	}
	fclose(fp);

	user[0] = '\0';
}

/* 回调函数，当收到每一个数据包时会被libpcap所调用 */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	ip_header* ih;
	mac_header* mh;
	u_int i = 0;

	int length = sizeof(mac_header) + sizeof(ip_header);
	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + 14); //length ofethernet header

	int name_point = 0;
	int pass_point = 0;
	int tmp;
	for (int i = 0; i < ih->tlen - 40; i++) {
		if (*(pkt_data + i) == 'U' && *(pkt_data + i + 1) == 'S' && *(pkt_data + i + 2) == 'E' && *(pkt_data + i + 3) == 'R') {
			name_point = i + 5;//'u' 's' 'e' 'r' ' '共5个字节,跳转至用户名第一个字节

			//到回车0x0d（ascii 13）换行（ascii 10）为止，前面的内容是用户名
			int j = 0;
			while (!(*(pkt_data + name_point) == 13 && *(pkt_data + name_point + 1) == 10)) {
				user[j] = *(pkt_data + name_point);//存储账号
				j++;
				++name_point;
			}
			user[j] = '\0';
			break;

		}

		if (*(pkt_data + i) == 'P' && *(pkt_data + i + 1) == 'A' && *(pkt_data + i + 2) == 'S' && *(pkt_data + i + 3) == 'S') {
			pass_point = i + 5;////'P' 'A' 'S' 'S' ' '共5个字节,跳转至密码第一个字节
			tmp = pass_point;

			//到回车0x0d（ascii 13）换行（ascii 10）为止，前面的内容是密码
			int k = 0;
			while (!(*(pkt_data + pass_point) == 13 && *(pkt_data + pass_point + 1) == 10)) {
				pass[k] = *(pkt_data + pass_point);//存储密码
				k++;
				++pass_point;

			}
			pass[k] = '\0';

			for (;; tmp++) {
				if (*(pkt_data + tmp) == '2' && *(pkt_data + tmp + 1) == '3' && *(pkt_data + tmp + 2) == '0') {
					output(ih, mh, header, (char*)user, (char*)pass, true);
					break;
				}
				else if (*(pkt_data + tmp) == '5' && *(pkt_data + tmp + 1) == '3' && *(pkt_data + tmp + 2) == '0') {
					output(ih, mh, header, (char*)user, (char*)pass, false);
					break;
				}
			}
			break;
		}
	}
}