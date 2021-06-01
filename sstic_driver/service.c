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
#include <string.h>



#include "sstic_lib.h"

#define PORT 1337

//#define HEXDUMP

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

#define MAX_SIZE 900000

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
    EXEC_CODE_OK,
    EXEC_CODE_ERROR,
    EXEC_FILE_KEY_OK,
    EXEC_FILE_BAD_KEY,
    EXEC_FILE_OK,
    EXEC_FILE_ERROR,
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
    { 0x33b755ca83b89f80, 0xffffffffffffffff },
    { 0x4dc5fbf6eaeb3c03, 0xffffffffffffffff },
    { 0x1484613095546231, 0xffffffffffffffff },
    { 0x3885d7f667d3ccad, 0xcc90ebfe },
    { 0x3c33734c39cf48f6, 0x0 },
    { 0xa4ba8897ece93c99, 0x0 },
    { 0xf920cc396b41598d, 0x1000 },
    { 0x289d88c88b08f87d, 0xffffffffffffffff },
    { 0x28a5e31d2ace16d3, 0xcc90ebfe },
    { 0x5aedd73c14bfd656, 0x0 },
    { 0xea14986b1acac130, 0x1000 }
};

const size_t NB_FILES = sizeof(file_perms) / sizeof(file_perms[0]);

uint64_t req_perms[NB_REQ_TYPE] = {0xffffffffffffffff, 0xffffffffffffffff, 0x100,0x10};

//code decrypting password

const char code_decrypt[] =
"\x4e\x01\x40\x20\x42\x1b\x00\x00\x09\x1b\x10\x00\x0c\xe3\x24\x10\x09\x02\x06\x00\x0c\x63\x1c\x10\x4c\x03\xac\x10\x00\x1b\x01\x00"
"\x4c\x03\x08\x10\x4e\x05\x00\x02\x19\x62\x01\x00\x1c\x23\xac\x10\x29\x41\x10\x02\x2c\xe3\x3c\x10\x4c\x03\xac\x10\x39\x21\x20\x02"
"\x3c\x23\xac\x10\x45\x16\x05\x00\x20\x17\x0d\x07\x27\x17\x10\x00\x20\x17\x00\x0c\x29\x02\x05\x00\x2c\x63\x60\x10\x4c\x03\xac\x10"
"\x45\x16\x05\x00\x20\x17\x06\x01\x27\x17\x10\x00\x20\x17\x0f\x02\x29\x02\x05\x00\x2c\x63\x7c\x10\x4c\x03\xac\x10\x19\x03\x08\x04"
"\x1c\x63\x88\x10\x4c\x03\xac\x10\x42\x1f\x00\x11\x49\x1f\x00\x13\x4c\xe3\xa8\x10\x4e\x04\x07\x00\x45\x06\x00\x00\x4f\x04\x07\x00"
"\x40\x1f\x10\x00\x4c\x03\x8c\x10\x7d\x03\x00\x11\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x4b\x05\x04\x0a\x41\x03\x49\x0b\x4c\xef\x21\x16\x4d\x1d\x06\x21\x4c\x18\x05\x3a\x48\x1a\x08\x0b\x40\x16\x0c\x07\x41\x02\x01\x01"
"\x41\x03\x03\x0a\x48\x03\x19\x0b\x4c\x0f\x09\x16\x4a\x1c\x01\x01\x47\x1c\x11\x0a\x44\xe7\x31\x19\x42\x17\x0d\x37\x41\x02\x00\x01"
"\x4e\x18\x15\x0a\x46\x00\x0f\x0b\x40\x17\x1d\x07\x41\x0a\x00\x01\x4e\x18\x15\x0a\x46\x08\x0f\x0b\x45\x16\x0b\x07\x4f\x19\x07\x01"
"\x4d\x19\x02\x0a\x4d\x12\x0c\x0b\x49\x16\x08\x07\x43\xa1\x9e\x10\x73\x00\xd5\x1b\x4a\x1f\x09\x3b\x4f\x0c\x0b\x07\x4f\x19\x16\x01"
"\x41\x07\x03\x0a\x48\x1f\x19\x0b\x4f\x04\x0b\x07\x4f\x19\x16\x01\x41\x0f\x03\x0a\x44\x07\x39\x1a\x2a\x08\x0d\x07\x25\x0a\x06\x01"
"\x24\x0b\x05\x0a\x22\x08\x09\x0b\x2a\x00\x0d\x07\x25\x0e\x06\x01\x73\x00\xd5\x1b\x22\x08\x09\x0b\x2a\x04\x0d\x07\x25\x0a\x06\x01"
"\x24\x07\x05\x0a\x22\x00\x09\x0b\x2a\x08\x0d\x07\x43\x01\x72\x10\x2e\x01\x04\x0a\x2d\x0a\x09\x0b\x42\x1a\x0e\x07\x28\x15\x16\x01"
"\x28\x0c\x15\x0a\x2c\x0a\x0c\x0b\x20\x06\x0e\x07\x2a\x04\x04\x01\x4c\x15\x04\x0a\x2f\x13\x05\x0b\x26\x0b\x19\x07\x2b\x04\x03\x01"
"\x2e\x01\x04\x0a\x2d\x0a\x09\x0b\x42\x1a\x0e\x07\x28\x15\x0e\x01\x28\x0c\x1d\x0a\x2c\x0a\x0c\x0b\x20\x06\x0e\x07\x2a\x04\x04\x01"
"\x4c\x15\x04\x0a\x2f\x13\x0e\x0b\x26\x0b\x14\x07\x2b\x04\x03\x01\x4e\x1c\x04\x0a\x03\x04\x09\x0b\x42\x0f\x0d\x27\x4d\x09\x06\x00"
"\x40\x06\x05\x3a\x46\x08\x0b\x0b\x20\x0a\x0d\x07\x4a\x04\x05\x01\x41\x06\x05\x3a\x48\x07\x19\x0b\x40\x07\x1d\x07\x41\x07\x16\x31"
"\x40\x0f\x07\x0a\x28\x02\x09\x0b\x45\x0a\x0e\x07\x40\x07\x16\x31\x4e\x00\x15\x0a\x48\x0f\x19\x0b\x4e\x09\x2d\x37\x41\x0e\x04\x01"
"\x2e\x05\x05\x0a\x4d\x02\x0a\x0b\x4f\x09\x2d\x37\x4f\x01\x16\x01\x4e\x08\x15\x0a\x46\x01\x39\x3b\x4e\x00\x0f\x07\x2f\x04\x06\x01"
"\x4b\x05\x06\x0a\x47\x01\x39\x3b\x0b\x0c\x0d\x07\x0f\x02\x06\x01\x0e\x03\x05\x0a\x08\x04\x09\x0b\x00\x0c\x0d\x07\x0f\x02\x06\x01"
"\x0e\x03\x05\x0a\x08\x04\x09\x0b\x00\x0c\x0d\x07\x0f\x02\x06\x01\x0e\x03\x05\x0a\x08\x04\x09\x0b\x00\x0c\x0d\x07\x0f\x02\x06\x01"
"\x0e\x03\x05\x0a\x08\x04\x09\x0b\x00\x0c\x0d\x07\x0f\x02\x06\x01\x0e\x03\x05\x0a\x08\x04\x09\x0b\x00\x0c\x0d\x07\x0f\x02\x06\x01";

void _read(int fd, unsigned char * buf, size_t size)
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
    _read(connfd, (unsigned char*)&id, 4);
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
    _read(connfd, (unsigned char*)&id,4);
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
        return;
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


#define BANNER_ERR_START "---DEBUG LOG START---\n"
#define BANNER_ERR_END "---DEBUG LOG END---\n"
void do_req_exec_code(int connfd, struct dec_payload *pt)
{
    size_t code_size, input_size, output_size;
    unsigned char code[0x1000] = {0};
    unsigned char input[0x1000] = {0};
    unsigned char output[0x1000] = {0};
    unsigned char errout[0x1000] = {0};
    int ret;

    _read(connfd, (unsigned char*)&code_size, sizeof(code_size));
    if (code_size > 0x1000)
    {
        fprintf(stderr,"code size too big\n");
        write(connfd, &(enum req_type){EXEC_CODE_ERROR},1);
        return;
    }

    _read(connfd, code, code_size);
    _read(connfd, (unsigned char*)&input_size, sizeof(input_size));
    if (input_size > 0x1000)
    {
        fprintf(stderr,"input size too big\n");
        write(connfd, &(enum req_type){EXEC_CODE_ERROR},1);
        return;
    }

    _read(connfd, input, input_size);
    //might seems weird but we ask client to send output size, so we don't have to send the whole page
    //people wanting to send a lot of request to fuzz a bit the ISA will be probably be happy to have that
    _read(connfd, (unsigned char*)&output_size, sizeof(output_size));

    if (output_size > 0x1000)
    {
        fprintf(stderr,"output size too big\n");
        write(connfd, &(enum req_type){EXEC_CODE_ERROR},1);
        return;
    }

    ret = exec_code(code, code_size, input, input_size, output, output_size, errout, 0x200);
    if(ret)
    {
        fprintf(stderr,"unexpected error while executing code\n");
        write(connfd, &(enum req_type){UNEXPECTED_ERROR}, 1);
        return;
    }

    write(connfd, &(enum req_type){EXEC_CODE_OK}, 1);
    write(connfd, output, output_size);
    write(connfd, BANNER_ERR_START, strlen(BANNER_ERR_START));
    write(connfd, errout, strlen((char*)errout));
    write(connfd, BANNER_ERR_END, strlen(BANNER_ERR_END));
}

#define BANNER_START "---EXEC OUTPUT START---\n"
#define BANNER_END "---EXEC OUTPUT END---\n"
void do_req_exec_file(int connfd, struct dec_payload *pt)
{
    size_t code_size, n;
    unsigned char code[0x1000] = {0};
    unsigned char input[0x1000] = {0};
    unsigned char output[0x1000] = {0};
    unsigned char errout[0x1000] = {0};
    unsigned char buf[0x1000] = {0};
    size_t executable_size, left, to_read, output_read = 0;
    int ret;
    char *rret;
    int exec_fd;
    int keyOK = 0;
    FILE * foutput;

    _read(connfd, input, 0x50);

    memcpy(code, code_decrypt, sizeof(code_decrypt));
    code_size = sizeof(code_decrypt);
    ret = exec_code(code, code_size, input, 0x50, output, 0x40, errout, 0 );
    if(ret)
    {
        fprintf(stderr,"unexpected error while executing code\n");
        write(connfd, &(enum req_type){UNEXPECTED_ERROR},1);
        return;
    }

#ifdef HEXDUMP
    hexdump(output,0x40);
#endif
    //checking password
    keyOK = 1;
    for(int i=0; i<0x30; i++)
    {
        if(output[i] != (unsigned char)0xff)
        {
            keyOK = 0;
            break;
        }
    }
    if(keyOK)
    {
        keyOK = !memcmp(output + 0x30, "EXECUTE FILE OK!", 0x10);
    }

    if(!keyOK)
    {
        fprintf(stderr,"wrong pass\n");
        write(connfd, &(enum req_type){EXEC_FILE_BAD_KEY}, 1);
        return;
    }
    else{
        fprintf(stderr,"good pass\n");
        write(connfd, &(enum req_type){EXEC_FILE_KEY_OK}, 1);
    }

    //ok receive file and execute it
    _read(connfd, (unsigned char*)&executable_size, sizeof(executable_size));

    //TODO check if 900 is enough
    if(executable_size > 900000)
    {
        fprintf(stderr,"executable too big\n");
        write(connfd, &(enum req_type){EXEC_FILE_ERROR},1);
        return;
    }

    exec_fd = open("/home/sstic/execfile", O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IXUSR);
    if(exec_fd == -1)
    {
        fprintf(stderr,"unexpected error while creating executable file\n");
        write(connfd, &(enum req_type){UNEXPECTED_ERROR},1);
        return;
    }
    left = executable_size;
    while(left)
    {
        to_read = left > 0x1000 ? 0x1000 : left;
        _read(connfd, buf, to_read);
        n = write(exec_fd, buf, to_read);
        if(n != to_read)
        {
            fprintf(stderr,"unexpected error while writing file\n");
            write(connfd, &(enum req_type){UNEXPECTED_ERROR},1);
            close(exec_fd);
            return;
        }
        left -= to_read;
    }
    close(exec_fd);

    foutput = popen("/home/sstic/execfile","r");
    if(!foutput)
    {
        fprintf(stderr,"unexpected error while writing file\n");
        write(connfd, &(enum req_type){UNEXPECTED_ERROR},1);
        return;
    }

    memset(buf,0,0x1000);
    //TODO double check this shit
    while(!feof(foutput) && output_read < 0xfff)
    {
        rret = fgets((char*)buf + output_read, 0x1000 - output_read - 1, foutput);
        if(!rret)
        {
	    //nothing to read
	    continue;
	    /*
            fprintf(stderr,"unexpected error while reading output\n");
            write(connfd, &(enum req_type){UNEXPECTED_ERROR},1);
            pclose(foutput);
            return;*/
        }
        n = strlen(rret);
        if (n + output_read >= 0x1000)
	{
		//shouldn't happen
		abort();
	}
        output_read += n;
    }
    pclose(foutput);
    remove("/home/sstic/execfile");

    write(connfd, &(enum req_type){EXEC_FILE_OK},1);
    write(connfd, BANNER_START, strlen(BANNER_START));
    write(connfd, buf, output_read);
    write(connfd, BANNER_END, strlen(BANNER_END));
}

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
		_read(connfd,(unsigned char*)&hdr, sizeof(hdr));
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
