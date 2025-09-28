#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/filter.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define PORT 1337
#define MAX_CLIENTS 50
#define BUFFER_SIZE 1024

typedef struct {
    uint32_t ip;
    uint16_t port;
} client_id_t;

typedef struct {
    int socket;
    struct sockaddr_in addr;
} client_info_t;

client_id_t boss_client = {0};
pthread_mutex_t boss_mutex = PTHREAD_MUTEX_INITIALIZER;

void welcome(int sockfd) {
    char* door[] = {
        "     /|\n",
        "    / |\n",
        "   /__|______\n",
        "  |  __  __  |\n",
        "  | |  ||  | | \n",
        "  | |__||__| |---\n",
        "  |  __  __()|\\ hello\n",
        "  | |  ||  | |\n",
        "  | |  ||  | |\n",
        "  | |__||__| |\n",
        "  |__________|\n"
    };
    for (int i=0; i<11; i++) {
        send(sockfd, door[i], strlen(door[i]), 0);
    }
    return;
}

void flag(int connfd) {
    FILE * fptr;
    char flag[100];
    int flag_buf = sizeof(flag);
    memset(flag, 0, flag_buf);
    fptr = fopen("./flag.txt", "r");
    if (fptr == NULL) return;
    if (fgets(flag, flag_buf, fptr) == NULL) return;
    fclose(fptr);
    write(connfd, flag, flag_buf);
    return;
}

int client_matches(struct sockaddr_in* client_addr) {
    pthread_mutex_lock(&boss_mutex);
    int match = (boss_client.ip == client_addr->sin_addr.s_addr && boss_client.port == client_addr->sin_port);
    if (match) memset(&boss_client, 0, sizeof(client_id_t));
    pthread_mutex_unlock(&boss_mutex);
    return match;
}

void *threadB(void *arg) {
    struct sock_fprog filter;
    struct sock_filter code[] = {
// tcpdump "tcp[((tcp[12]&0xf0)>>2):4]==0xff00fe01 and tcp[((tcp[12]&0xf0)>>2)+4:4]==0x736b6264 and tcp[((tcp[12]&0xf0)>>2)+12:4]==0x646f677a" -dd
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 31, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 29, 0x00000006 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 27, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x50, 0, 0, 0x0000001a },
{ 0x54, 0, 0, 0x000000f0 },
{ 0x74, 0, 0, 0x00000002 },
{ 0xc, 0, 0, 0x00000000 },
{ 0x7, 0, 0, 0x00000000 },
{ 0x40, 0, 0, 0x0000000e },
{ 0x15, 0, 19, 0xff00fe01 },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x50, 0, 0, 0x0000001a },
{ 0x54, 0, 0, 0x000000f0 },
{ 0x74, 0, 0, 0x00000002 },
{ 0x4, 0, 0, 0x00000004 },
{ 0xc, 0, 0, 0x00000000 },
{ 0x7, 0, 0, 0x00000000 },
{ 0x40, 0, 0, 0x0000000e },
{ 0x15, 0, 10, 0x736b6264 },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x50, 0, 0, 0x0000001a },
{ 0x54, 0, 0, 0x000000f0 },
{ 0x74, 0, 0, 0x00000002 },
{ 0x4, 0, 0, 0x0000000c },
{ 0xc, 0, 0, 0x00000000 },
{ 0x7, 0, 0, 0x00000000 },
{ 0x40, 0, 0, 0x0000000e },
{ 0x15, 0, 1, 0x646f677a },
{ 0x6, 0, 0, 0x00040000 },
{ 0x6, 0, 0, 0x00000000 },
    };
    filter.len = sizeof(code)/sizeof(code[0]);
    filter.filter = code;
    
    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sock < 1) return NULL;
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == -1) return NULL;
    char buffer[BUFFER_SIZE];
    while (1) {
        ssize_t len = recv(sock, buffer, sizeof(buffer), 0);
        if (len <= 0) continue;

        struct iphdr* iph = (struct iphdr*)(buffer + 14);
        if (iph->protocol != IPPROTO_TCP) continue;

        int ip_header_len = iph->ihl * 4;
        struct tcphdr* tcph = (struct tcphdr*)(buffer + 14 + ip_header_len);

        client_id_t cid = {
            .ip = iph->saddr,
            .port = tcph->source 
        };

        pthread_mutex_lock(&boss_mutex);
        boss_client = cid;
        pthread_mutex_unlock(&boss_mutex);

    }

    close(sock);
    return NULL;
}

void *handle_client(void* arg) {
    client_info_t client = *(client_info_t*)arg;
    free(arg);

    welcome(client.socket);

    char buf[BUFFER_SIZE];
    while (1) {
        ssize_t n = recv(client.socket, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;

        int match = client_matches(&client.addr);
        if (match) {
        flag(client.socket);
        } else {
            send(client.socket, "no\n", 3, 0);
        }
    }

    return NULL;
}

void *threadA(void *arg) {
    struct sockaddr_in addr;
    int opt = 1;
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 1)  return NULL;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) return NULL;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, MAX_CLIENTS);

    while(1) {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addrlen);

        if (client_fd < 0) continue;

        client_info_t* info = malloc(sizeof(client_info_t));
        info->socket = client_fd;
        info->addr = client_addr;

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, info);
        pthread_detach(tid);
    }

    return NULL;
}

int main() {

    pthread_t tcp_thread, raw_thread;

    pthread_create(&tcp_thread, NULL, threadA, NULL);
    pthread_create(&raw_thread, NULL, threadB, NULL);
    
    pthread_join(tcp_thread, NULL);
    pthread_join(raw_thread, NULL);

    return 0;
}