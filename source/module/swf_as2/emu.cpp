/*
*  Interactive disassembler (IDA).
*  Adobe Flash ActionScript2 processor module
*  Marian RADU <marianra@microsoft.com>
*/

#include <idaidp.hpp>

static void TouchArg( op_t &x, bool bRead )
{
    switch( x.type )
    {
    case o_near:
        if (x.dtyp == dt_string)
            break;
        // mark the reference of a jump / call
        ua_add_cref( 0, x.addr, InstrIsSet(cmd.itype, CF_CALL) ? fl_CN : fl_JN);
        break;
    }
}

int __stdcall emu( )
{
    uint32 Feature = cmd.get_canon_feature();

    if((Feature & CF_STOP) == 0)
        ua_add_cref( 0, cmd.ea+cmd.size, fl_F );

    if( Feature & CF_USE1 )   TouchArg( cmd.Op1, 1 );
    if( Feature & CF_USE2 )   TouchArg( cmd.Op2, 1 );
    if( Feature & CF_USE3 )   TouchArg( cmd.Op3, 1 );
    if( Feature & CF_USE4 )   TouchArg( cmd.Op4, 1 );
    if( Feature & CF_USE5 )   TouchArg( cmd.Op5, 1 );
    if( Feature & CF_USE6 )   TouchArg( cmd.Op6, 1 );
    //if( Feature & CF_CHG1 )   TouchArg( cmd.Op1, 0 );

    return 1;
}
