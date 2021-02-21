#ifndef SSTIC_H
#define SSTIC_H

#include <linux/ioctl.h>

#define SSTIC_RD 1
#define SSTIC_WR 2

#define STDINNO 0
#define STDOUTNO 1
#define STDERRNO 2
#define CODENO 3


struct sstic_arg_alloc
{
    unsigned int nb_pages;
    unsigned int flags;
    unsigned int id;
};

struct sstic_arg_del
{
    unsigned int id;
};

struct sstic_arg_assoc
{
    unsigned int id;
    unsigned int type;
};

struct sstic_submit_command
{
    unsigned int opcode;
};

struct sstic_get_key
{
    unsigned long id;
    char key[16];
};

struct sstic_get_debug_state
{
    int debug_state;
};

union sstic_arg
{
    struct sstic_arg_alloc alloc;
    struct sstic_arg_del del;
    struct sstic_arg_assoc assoc;
    struct sstic_submit_command command;
    struct sstic_get_key get_key;
    struct sstic_get_debug_state debug_state;
};

#define ALLOC_REGION _IOWR('S', 0, union sstic_arg)
#define DEL_REGION _IOWR('S', 1, union sstic_arg)
#define ASSOC_REGION _IOWR('S', 2, union sstic_arg)
#define SUBMIT_COMMAND _IOWR('S', 3, union sstic_arg)
#define GET_KEY _IOWR('S', 4, union sstic_arg)
#define GET_DEBUG_STATE _IOWR('S', 5, union sstic_arg)

#define OPCODE_WB_DEC 1
#define OPCODE_EXEC_CODE 2



#endif
