#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <assert.h>

#include <ctype.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>


#include "sstic.h"
#include "sstic_lib.h"

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

const char code_decrypt[] = "\x45\x06\x01\x00\x49\x07\x40\x00\x4c\xe3\x2c\x10\x42\x1f\x00\x20\x42"
"\x1b\x00\x30\x40\x1e\x01\x00\x40\x1a\x01\x00\x4e\x00\x07\x00\x4f"
"\x00\x06\x00\x40\x07\x10\x00\x4c\x03\x04\x10\x45\x1e\x07\x00\x49"
"\x1f\x14\x00\x4c\xe3\x38\x11\x42\x1b\x00\x30\x4e\x00\x06\x00\x40"
"\x1b\x10\x00\x4e\x04\x06\x00\x40\x1b\x10\x00\x4e\x08\x06\x00\x40"
"\x1b\x10\x00\x4e\x0c\x06\x00\x45\x1a\x06\x00\x40\x1b\x01\x00\x43"
"\x1a\x07\x00\x45\x16\x05\x00\x49\x1a\x05\x00\x4c\xa3\x98\x10\x7d"
"\x03\xd0\x10\x42\x1b\x00\x30\x4f\x00\x06\x00\x40\x1b\x10\x00\x4f"
"\x04\x06\x00\x40\x1b\x10\x00\x4f\x08\x06\x00\x40\x1b\x10\x00\x4f"
"\x0c\x06\x00\x4c\x03\x30\x10\x2a\x04\x00\x00\x2a\x08\x00\x00\x2a"
"\x08\x00\x00\x2a\x0c\x00\x00\x2a\x0c\x00\x00\x2a\x0c\x00\x00\x7d"
"\x03\xd0\x10\x2a\x0c\x00\x00\x2a\x08\x00\x00\x2a\x08\x00\x00\x2a"
"\x04\x00\x00\x2a\x04\x00\x00\x2a\x04\x00\x00\x4c\x03\x74\x10\x20"
"\x02\x01\x00\x25\x0e\x00\x00\x42\x16\x03\x00\x27\x17\x10\x00\x26"
"\x0f\x10\x00\x24\x0e\x05\x00\x20\x0a\x03\x00\x25\x06\x02\x00\x42"
"\x16\x01\x00\x27\x17\x0c\x00\x26\x07\x14\x00\x24\x06\x05\x00\x20"
"\x02\x01\x00\x25\x0e\x00\x00\x42\x16\x03\x00\x27\x17\x08\x00\x26"
"\x0f\x18\x00\x24\x0e\x05\x00\x20\x0a\x03\x00\x25\x06\x02\x00\x42"
"\x16\x01\x00\x27\x17\x07\x00\x26\x07\x19\x00\x24\x06\x05\x00\x40"
"\x1f\x01\x00\x0b\x00\x00\x00\x42\x03\x00\x20\x42\x0b\x00\x01\x4e"
"\x05\x00\x30\x4e\x0c\x02\x00\x20\x06\x00\x00\x45\x04\x02\x00\x4f"
"\x05\x00\x30\x40\x03\x10\x00\x40\x0b\x10\x00\x4e\x05\x10\x30\x4e"
"\x0c\x02\x00\x20\x06\x00\x00\x45\x04\x02\x00\x4f\x05\x10\x30\x40"
"\x03\x10\x00\x40\x0b\x10\x00\x4e\x05\x20\x30\x4e\x0c\x02\x00\x20"
"\x06\x00\x00\x45\x04\x02\x00\x4f\x05\x20\x30\x40\x03\x10\x00\x40"
"\x0b\x10\x00\x4e\x05\x30\x30\x4e\x0c\x02\x00\x20\x06\x00\x00\x45"
"\x04\x02\x00\x4f\x05\x30\x30\x0b\x00\x00\x00";


void test_exec_code()
{
    size_t code_size, input_size, output_size;
    char code[0x1000] = {0};
    char input[0x1000] = {0};
    char output[0x1000] = {0};
    char errout[0x1000] = {0};

    for(int i=0; i<0x40; i++)
    {
	    input[i] = i;
    }
    memcpy(code, code_decrypt, sizeof(code_decrypt));
    int ret = exec_code(code, sizeof(code_decrypt), input, 0x40, output, 0x40, errout, 0x200 );
    if(ret == -1)
    {
	    perror("exec_code");
	    abort();
    }
    hexdump(output,0x40);
    printf("stderr : %s\n", errout);
}

int main()
{
    int session1 = open("/dev/sstic", O_RDWR);
    unsigned int region_rd = allocate_region(session1, 4, SSTIC_RD);
    perror("region_rd");
    assert(region_rd == 0x1000);
    unsigned int region_wr = allocate_region(session1, 4, SSTIC_WR);
    assert(region_wr == 0x2000);
    unsigned int region_rd_wr = allocate_region(session1, 8, SSTIC_RD | SSTIC_WR);
    assert(region_rd_wr == 0x3000);
    unsigned int region_rd_wr2 = allocate_region(session1, 8, SSTIC_RD | SSTIC_WR);
    assert(region_rd_wr2 == 0x4000);

    char* map_rd = mmap(NULL, 0x4000, PROT_READ, MAP_SHARED, session1, region_rd);
    perror("test1");
    assert((long)map_rd != -1);
    char* map_rd2 = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_SHARED, session1, region_rd);
    assert((long)map_rd2 == -1);
    char *map_wr = mmap(NULL, 0x4000, PROT_WRITE, MAP_SHARED, session1, region_wr);
    assert((long)map_wr != -1);
    char *map_wr2 = mmap(NULL, 0x4000, PROT_WRITE | PROT_READ, MAP_SHARED, session1, region_wr);
    assert((long)map_wr2 == -1);
    char *map_wr_rd = mmap(NULL, 0x6000, PROT_WRITE | PROT_READ, MAP_SHARED, session1, region_rd_wr);
    assert((long)map_wr_rd == -1);
    char *map_wr_rd2 = mmap((void*)0x500001000, 0x8000, PROT_WRITE | PROT_READ, MAP_FIXED | MAP_SHARED, session1, region_rd_wr2);
    assert((long)map_wr_rd2 != -1);
    printf("map : %p\n",map_rd);
    
    hexdump(map_rd,0x100);
    hexdump(map_rd + 0x1000,0x10);
    hexdump(map_rd + 0x2000,0x10);
    //shexdump(map_rd + 0x3000,0x10);
    //del_region(session1, region_rd_wr);
    //abort();
  
    
    for(int i=0; i<8; i++)
    {
        *(map_wr_rd2 + 0x1000 * i) = 0x40 + i;
    }
     for(int i=0; i<8; i++)
    {
        hexdump(map_wr_rd2 + 0x1000 * i,0x10) ;
    }
    map_wr_rd2 = (char*)mremap(map_wr_rd2, 0x8000, 0x8000, 3, 0x600001000UL);
    printf("new %p\n", map_wr_rd2);
    map_wr_rd2 = (char*)0x600001000UL;
    munmap(map_wr_rd2 + 0x2000,0x1000);
    
    for(int i=0; i<8; i++)
    {
        if(i==2)
            continue;
        hexdump(map_wr_rd2 + 0x1000 * i,0x10) ;
    }
    close(session1);

    char ct[16] = {0};
    char pt[16] = {0};
    char key[16] = {0};
    unsigned int id = 1;

    printf("TEST CODE\n");
    test_exec_code();
/*pt:
00000000: 78 56 34 12 78 56 34 12  11 11 11 01 00 00 00 00  xV4.xV4.........
key = 
00000000: 4E E8 11 31 17 8D 23 30  CA 4A 24 79 1C DE B6 50  N..1..#0.J$y...P
00000000: 62 78 06 EB DD E4 E0 38  12 02 9B 12 25 83 14 96  bx.....8....%...
*/
    memcpy(ct, "\x62\x78\x06\xEB\xDD\xE4\xE0\x38\x12\x02\x9B\x12\x25\x83\x14\x96", 16);
    id = 0x60313d9f;
    wb_decrypt(ct,id,pt);
    printf("test decrypt\n");
    hexdump(pt,0x10);
    assert(!memcmp(pt, "\x78\x56\x34\x12\x78\x56\x34\x12\x11\x11\x11\x01\x00\x00\x00\x00", 16));

    sstic_getkey(key,0x4307121376ebbe45);
    assert(!memcmp(key, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16));
    sstic_getkey(key,0x0906271dff3e20b4);
    assert(!memcmp(key, "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f", 16));
    sstic_getkey(key,0x7e0a6dea7841ef77);
    assert(!memcmp(key, "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f", 16));
    //sstic_getkey(key,0x9c92b27651376bfb);
/*
    ret = mremap(map_wr_rd2 + 0x3000, 0x5000, 0x5000, 3, 0x600001000);
    printf("%d\n",ret);
    if(ret == -1)
        perror("mremap");
    for(int i=0; i<5; i++)
    {
        hexdump(0x600001000 + 0x1000 * i,0x10) ;
    }
    hexdump(map_wr_rd2 + 0x3000,0x10);*/
    

  

}
