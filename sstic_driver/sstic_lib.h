#ifndef SSTIC_LIB_H
#define SSTIC_LIB_H

#include <stdint.h>

unsigned int allocate_region(int fd, size_t nb_pages, int flags);
int assoc_region(int fd, unsigned int id, int type);
int submit_command(int fd, unsigned long opcode);
int wb_decrypt(char ct[16], unsigned int id, char pt[16]);
int sstic_getkey(char key[16], uint64_t id);
int get_debug_mode();


#endif