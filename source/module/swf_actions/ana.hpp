/*
*  Interactive disassembler (IDA).
*  Adobe Flash ActionScript2 processor module
*  Marian RADU <marianra@microsoft.com>
*/

#ifndef __ANA_HPP
#define __ANA_HPP

#include "ins.hpp"

extern uint16   instruction_lookup[];
extern uint8    opcode_lookup[];

#define o_null      o_idpspec0
#define o_undefined o_idpspec1
#define o_bool      o_idpspec2
#define o_const     o_idpspec3
#define o_string    o_idpspec4

int __stdcall ana( void );

#endif