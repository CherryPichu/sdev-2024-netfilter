#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include "pcap-test.h"

#include <libnetfilter_queue/libnetfilter_queue.h>


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, char* forbiddenHost) {
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);

	if (ph) {
		id = ntohl(ph->packet_id);
	}

	ret = nfq_get_payload(tb, &data); // ip table

	if (ret >= 1){
		struct libnet_ipv4_hdr * ip_info = (struct iphdr *)data;
		if(ip_info->ip_p == IPPROTO_TCP) {
			int ip_hdr_len = (ip_info->ip_init & 0x0F) * 4;
			data += ip_hdr_len;
			struct libnet_tcp_hdr* tcp_info = (struct libnet_tcp_hdr*)(data);
			unsigned short dest_port = ntohs(tcp_info->th_dport);
			unsigned short source_port = ntohs(tcp_info->th_sport);

			if(dest_port == 80){
				int tcp_hdr_len = ((ntohs(tcp_info->th_flags)& 0xF000) >> 12) * 4;
				data += tcp_hdr_len;
				int http_hdr_length = ret - (ip_hdr_len + tcp_hdr_len);

				// copy data to http_res
				char http_res[http_hdr_length];
				for (int i = 0; i < http_hdr_length; i++) {
					if (i != 0 && i % 16 == 0)
						http_res[i] = "\n";
					http_res[i] = data[i];
				}

				// copy host of data to http_host
				char* hostname[1000];
				find_host(http_res, hostname);
				

				if(isGetMethod(http_res) ){
					char* res = strstr(hostname, forbiddenHost);
					
					if(res == NULL){
						printf("%s\n", http_res);
					}else{
						printf("Error : Forbidden Host\n");
						id = -1;
					}
						
				};

			}
			
		}
	}
	
    


	fputc(0, stdout);

	return id;
}

// using chatgpt.....
void find_host(char input[], char* buf){ // Warring : stack overflow attack is possible.
	// "Host: " 문자열을 찾습니다.
    char *hostStart = strstr(input, "Host: ");
	if (hostStart != NULL) {
        // "Host: " 문자열을 찾은 경우, 실제 호스트 이름의 시작 위치를 계산합니다.
        // "Host: "의 길이만큼 포인터를 이동시킵니다.
        hostStart += strlen("Host: ");
        
        // 호스트 이름의 끝을 찾습니다. (다음 줄바꿈 문자까지)
        char *hostEnd = strchr(hostStart, '\n');
        if (hostEnd != NULL) {
            // 호스트 이름을 복사하기 위한 임시 버퍼를 준비합니다.
            
            // 호스트 이름을 임시 버퍼로 복사합니다.
            strncpy(buf, hostStart, hostEnd - hostStart);
            // 문자열의 끝을 나타내는 널 문자를 추가합니다.
            buf[hostEnd - hostStart] = '\0';
        }
    }
}

/*
 if return is 0, the http request is not GET method.
 if return is 1, the http request is GET method
*/
int isGetMethod(char* str){
	char* GET = "GET";
	for(int i = 0; i < 3; i++){
		if(str[i] != GET[i])
			return 0;
	}
	return 1;
}


void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%c", buf[i]);
	}
	printf("\n");
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	char** args = (char *) data;
	char* arg = args[1];

	u_int32_t id = print_pkt(nfa, arg);
	// printf("entering callback\n");
	if(id == -1){
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}else{
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	
}

int main(int argc, char *argv[])
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, argv);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			// printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}

		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");

		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);


#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif
	printf("closing library handle  \n");
	nfq_close(h);

	exit(0);
}
