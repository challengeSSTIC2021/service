#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>



#include "sstic_lib.h"

#define PORT 1337

#ifdef HEXDUMP
#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif
void hexdump(void *mem, unsigned int len)
{
        unsigned int i, j;

        for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
        {
                /* print offset */
                if(i % HEXDUMP_COLS == 0)
                {
                        printf("0x%06x: ", i);
                }

                /* print hex data */
                if(i < len)
                {
                        printf("%02x ", 0xFF & ((char*)mem)[i]);
                }
                else /* end of block, just aligning for ASCII dump */
                {
                        printf("   ");
                }

                /* print ASCII dump */
                if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
                {
                        for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
                        {
                                if(j >= len) /* end of block, not really printing */
                                {
                                        putchar(' ');
                                }
                                else if(isprint(((char*)mem)[j])) /* printable char */
                                {
                                        putchar(0xFF & ((char*)mem)[j]);
                                }
                                else /* other char */
                                {
                                        putchar('.');
                                }
                        }
                        putchar('\n');
                }
        }
}
#endif


//SERVICE

#define MAX_SIZE 500000

struct header{
    uint8_t req_no;
    char payload[16];
};

struct dec_payload
{
    uint64_t id;
    uint64_t perm;
};

enum req_type
{
    REQ_CHECK,
    REQ_GET_KEY,
    REQ_EXEC_CODE,
    REQ_EXEC_FILE,
    NB_REQ_TYPE
};

enum resp_type
{
    ACK,
    CHECK_OK,
    CHECK_EXPIRED,
    GETKEY_OK,
    GETKEY_EXPIRED,
    GETKEY_INV_PERMS,
    GETKEY_UNKOWN,
    GETKEY_DEBUG_DEVICE,
    REQ_ERROR = 0xfe,
    UNEXPECTED_ERROR = 0xff
};

#define WB_TIMEOUT 3600


struct file_info
{
    uint64_t id;
    uint64_t perm;
};


// perm 0 = forbidden for everyone (can only be retrieved with shell access)
// first file: accessible for everyone
// second: need to break wb to put good perm < 0x10000
// third: need to get shell access to perform the gey_key locally (service will refuse as perm is 0)
// fourth: need to pwn kernel to write in DEBUG_MODE pci register (but accessible through service after)
const struct file_info file_perms[] = {
    {0x4307121376ebbe45, 0xffffffffffffffff},
    {0x0906271dff3e20b4, 0x10000},
    {0x7e0a6dea7841ef77, 0},
    {0x9c92b27651376bfb, 2}}; //this last one needs prod key

const size_t NB_FILES = sizeof(file_perms) / sizeof(file_perms[0]);

uint64_t req_perms[NB_REQ_TYPE] = {0xffffffffffffffff, 0xffffffffffffffff, 0x100,0x10};

void _read(int fd, char * buf, size_t size)
{
	size_t recved = 0;
    int n = 0;
    if(size > MAX_SIZE)
    {
        fprintf(stderr, "message too big\n");
        abort();
    }
	while (recved < size)
    {
		n = read(fd, buf + recved, size - recved);
        if(n < 0)
        {
            fprintf(stderr, "error while reading\n");
            abort();
        }
        recved += n;
    }
}



void do_req_check(int connfd, struct header *hdr)
{
    int ret;
    unsigned int id;
    char pt[16];
    int ts = time(NULL);
    _read(connfd, (char*)&id, 4);
    enum resp_type resp = 0;
    ret = wb_decrypt(hdr->payload, id, pt);
    if(ret)
    {
        fprintf(stderr,"unexpected error while decrypting\n");
        write(connfd, &(enum req_type){UNEXPECTED_ERROR},1);
        return;
    }
    if(ts > id && WB_TIMEOUT + id > ts)
    {
        fprintf(stderr,"check OK\n");
        resp = CHECK_OK;
        write(connfd, &resp, 1);
    }
    else
    {
        fprintf(stderr,"check EXPIRED\n");
        resp = CHECK_EXPIRED;
        write(connfd, &resp,1);
    }
    write(connfd,pt,16);
}

int perms_req_valid(enum req_type req, uint64_t perm)
{
    return perm <= req_perms[req];
}

int dec_check_hdr(int connfd, struct header* hdr, struct dec_payload* pt)
{
    int ret;
    unsigned int id;
    int ts = time(NULL);
    _read(connfd, (char*)&id,4);
    if(WB_TIMEOUT + id <= ts)
    {
        fprintf(stderr,"get key expired\n");
        write(connfd, &(enum req_type){GETKEY_EXPIRED},1);
        return -1;
    }
    ret = wb_decrypt(hdr->payload, id, (char*)pt);
    if(ret)
    {
        fprintf(stderr,"unexpected error while decrypting\n");
        write(connfd, &(enum req_type){UNEXPECTED_ERROR},1);
        return ret;
    }
    if(!perms_req_valid(hdr->req_no, pt->perm))
    {
        fprintf(stderr,"bad perms for this req type\n");
        write(connfd, &(enum req_type){REQ_ERROR}, 1);
        return -1;
    }
    return 0;
}




void do_req_get_key(int connfd, struct dec_payload *pt)
{
    char key[16];
    int i;
    int want_debug = pt->id >> 63;
    int debug_mode = get_debug_mode();
    int ret;
    if(debug_mode == -1)
    {
        fprintf(stderr,"unexpected error while decrypting\n");
        write(connfd, &(enum req_type){UNEXPECTED_ERROR},1);
        return;
    }
    if(want_debug && debug_mode == 1)
    {
        fprintf(stderr,"trying to access prod key while device is in debug mode!\n");
        write(connfd, &(enum req_type){GETKEY_DEBUG_DEVICE},1);
    }
    //checking perm
    for(i=0; i<NB_FILES; i++)
    {
        if(file_perms[i].id == pt->id)
        {
            if(file_perms[i].perm && pt->perm <= file_perms[i].perm)
            {
                //OK!
                ret = sstic_getkey(key, pt->id);
                if(ret == -1)
                {
                    fprintf(stderr,"unexpected error while decrypting\n");
                    write(connfd, &(enum req_type){UNEXPECTED_ERROR},1);
                    return;
                }
                write(connfd, &(enum req_type){GETKEY_OK},1);
                write(connfd, key, 16);
                return;
            }
            else{
                fprintf(stderr,"bad perms\n");
                write(connfd, &(enum req_type){GETKEY_INV_PERMS},1);
                return;
            }
        }
    }
    fprintf(stderr,"file not found\n");
    write(connfd, &(enum req_type){GETKEY_UNKOWN},1);
}

void do_req_exec_code(int connfd, struct dec_payload *pt)
{}
void do_req_exec_file(int connfd, struct dec_payload *pt)
{}

int main()
{
    struct header hdr;
    struct dec_payload pt;
    enum resp_type resp;
    int ret;

    int sockfd, connfd;
    socklen_t len;
    struct sockaddr_in servaddr, cli;

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket listen\n");
        abort();
    }
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        perror("bind\n");
        abort();
    }

    printf("service started!\n");
    // Now server is ready to listen and verification
    if ((listen(sockfd, 1)) != 0) {
        perror("listen\n");
        abort();
    }
    len = sizeof(cli);

    // Accept the data packet from client and verification
    connfd = accept(sockfd, (struct sockaddr *)&cli, &len);
    if (connfd < 0) {
        perror("server acccept\n");
        abort();
    }
	write(connfd,"STIC",4);
	while(1)
	{
        _read(connfd,(char*)&hdr, sizeof(hdr));
        if(hdr.req_no >= NB_REQ_TYPE)
        {
            fprintf(stderr,"bad reqno\n");
            write(connfd, &(enum req_type){REQ_ERROR},1);
            continue;
        }
        //req check special case
        if((enum req_type)hdr.req_no == REQ_CHECK)
        {
            do_req_check(connfd, &hdr);
            continue;
        }
        //decrypt and check perms of req type
        ret = dec_check_hdr(connfd, &hdr, &pt);
        if(ret == -1)
        {
            //we already sended error code in dec_check_hdr
            continue;
        }
        //OK, perform request!
        switch((enum req_type)hdr.req_no)
        {
            case REQ_GET_KEY:
                do_req_get_key(connfd, &pt);
                break;
            case REQ_EXEC_CODE:
                do_req_exec_code(connfd, &pt);
                break;
            case REQ_EXEC_FILE:
                do_req_exec_file(connfd, &pt);
                break;
            default:
                resp = REQ_ERROR;
                write(connfd, &resp, 1);
                break;
        }
	}
}
