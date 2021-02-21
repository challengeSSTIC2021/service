#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <assert.h>
#include "sstic.h"
#include "sstic_lib.h"

#include <sys/mman.h>
#include <string.h>
#include <stdint.h>



unsigned int allocate_region(int fd, size_t nb_pages, int flags)
{
    union sstic_arg arg;
    arg.alloc.nb_pages = nb_pages;
    arg.alloc.flags = flags;
    int ret = ioctl(fd, ALLOC_REGION, &arg);
    if(ret == -1)
    {
        perror("allocate region");
        abort();
    }
    return arg.alloc.id;
}
/*
static void del_region(int fd, unsigned int id)
{
    union sstic_arg arg;
    arg.del.id = id;
    int ret = ioctl(fd, DEL_REGION, &arg);
    if(ret == -1)
    {
        perror("del region");
        //sleep(10);
        abort();
    }
}*/

int assoc_region(int fd, unsigned int id, int type)
{
    union sstic_arg arg;
    arg.assoc.id = id;
    arg.assoc.type = type;
    int ret = ioctl(fd, ASSOC_REGION, &arg);
    if(ret == -1)
    {
        perror("assoc region");
        return ret;
    }
    return 0;
}

int submit_command(int fd, unsigned long opcode)
{
    int ret;
    union sstic_arg arg;
    arg.command.opcode = opcode;
    ret = ioctl(fd, SUBMIT_COMMAND, &arg);
    if(ret == -1)
    {
        perror("submit command");
        return -1;
    }
    return 0;
}

struct dec_payload
{
    uint8_t buf[16];
    unsigned long id;
};


int wb_decrypt(char ct[16], unsigned int id, char pt[16])
{
    int ret;
    int session = open("/dev/sstic", O_RDWR);
    if(session == -1)
    {
        perror("open session");
        ret = -1;
        goto out;
    }
    unsigned int rstdin = allocate_region(session, 1, SSTIC_RD | SSTIC_WR);
    unsigned int rstdout = allocate_region(session, 1, SSTIC_RD );
    ret = assoc_region(session, rstdin,STDINNO);
    if(ret)
    {
        goto out_close;
    }
    assoc_region(session, rstdout,STDOUTNO);
    if(ret)
    {
        goto out_close;
    }
    struct dec_payload *map_stdin = mmap(NULL,0x1000, PROT_READ | PROT_WRITE, MAP_SHARED , session, rstdin);
    if((long)map_stdin == -1)
    {
        perror("map stdin");
        goto out_close;
    }
    char *map_stdout = mmap(NULL,0x1000, PROT_READ , MAP_SHARED , session, rstdout);
    if((long)map_stdout == -1)
    {
        perror("map stdout");
        goto out_stdin;
        return -1;
    }
    memcpy(map_stdin->buf,ct,16);
    map_stdin->id = id;
    ret = submit_command(session, OPCODE_WB_DEC);
    if((long)map_stdout == -1)
    {
        goto out_stdout;
        return -1;
    }
    //hexdump(map_stdout, 0x10);
    memcpy(pt, map_stdout, 16);
    out_stdout:
        munmap(map_stdout, 0x1000);
    out_stdin:
        munmap(map_stdin, 0x1000);
    out_close:
        close(session);
    out:
        return ret;
}

int sstic_getkey(char key[16], uint64_t id)
{
    int ret;
    union sstic_arg arg;
    arg.get_key.id = id;
    int session = open("/dev/sstic", O_RDWR);
    if(session == -1)
    {
        perror("open session");
        abort();
    }
    ret = ioctl(session, GET_KEY, &arg);
    if(ret == -1)
    {
        perror("get_key");
        return -1;
    }
    memcpy(key, arg.get_key.key,16);
    close(session);
    return 0;
    //hexdump(key,16);
}

int get_debug_mode()
{
    int ret;
    union sstic_arg arg;
    int session = open("/dev/sstic", O_RDWR);
    if(session == -1)
    {
        perror("open session");
        return -1;
    }
    ret = ioctl(session, GET_DEBUG_STATE, &arg);
    if(ret == -1)
    {
        perror("get_debug_state");
        return -1;
    }
    close(session);
    return arg.debug_state.debug_state;
}