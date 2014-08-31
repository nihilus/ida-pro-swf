/*
*  Interactive disassembler (IDA).
*  Adobe Flash ActionScript2 processor module
*  Marian RADU <marianra@microsoft.com>
*/


#include "../idaidp.hpp"

#ifndef __OUT_HPP
#define __OUT_HPP

void __stdcall header  ( void );
void __stdcall footer  ( void );
void __stdcall segstart( ea_t );
void __stdcall segend  ( ea_t );

void __stdcall out( void );
bool __stdcall outop( op_t &x );

#endif
