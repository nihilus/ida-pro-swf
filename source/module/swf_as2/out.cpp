/*
*  Interactive disassembler (IDA).
*  Adobe Flash ActionScript2 processor module
*  Marian RADU <marianra@microsoft.com>
*/

#include <idaidp.hpp>
#include "ana.hpp"
#include "out.hpp"

void __stdcall header( void )
{
  gen_cmt_line( "Processor:        %s", inf.procName );
  gen_cmt_line( "Target assembler: %s", ash.name );
  gen_cmt_line( "Byte sex        : %s", inf.mf ? "Big endian" : "Little endian");
}

void __stdcall footer( void ){;}

void __stdcall segstart( ea_t ea )
{
  /*segment_t *Sarea = getseg( ea );

  char sname[MAXNAMELEN];
  get_segm_name(Sarea, sname, sizeof(sname));

  gen_cmt_line( COLSTR("TAG %s", SCOLOR_AUTOCMT), sname );
  */
}

void __stdcall segend( ea_t ea ) {;}

void out_char (char c, color_t t)
{
    char str[]={c, 0};
    out_line(str, t);
}

uint8 is_printable(uint8 c)
{
    return ((c >= 0x20) && (c <= 0x7E))?1:0;
}

void __stdcall out( void )
{
    char buf[MAXSTR];

    init_output_buffer(buf, sizeof(buf));
    OutMnem();

    if (cmd.Op1.type != o_void)
    {
        // output first operand
        out_one_operand( 0 );
    }

    if( cmd.Op2.type != o_void )
    {
        //pading
        out_symbol( ',' );
        OutChar( ' ' );
        // output second operand
        out_one_operand( 1 );
    }

    if( cmd.Op3.type != o_void )
    {
        //pading
        out_symbol( ',' );
        OutChar( ' ' );
        // output third operand
        out_one_operand( 2 );
    }

    if( cmd.Op4.type != o_void )
    {
        //pading
        out_symbol( ',' );
        OutChar( ' ' );
        // output fourth operand
        out_one_operand( 3 );
    }

    if( cmd.Op5.type != o_void )
    {
        //pading
        out_symbol( ',' );
        OutChar( ' ' );
        // output fifth operand
        out_one_operand( 4 );
    }

    if( cmd.Op6.type != o_void )
    {
        //pading
        out_symbol( ',' );
        OutChar( ' ' );
        // output sixth operand
        out_one_operand( 5 );
    }

    //more processing due to instructions
    //having more than 6 operands
    op_t op;
    op.flags = OF_SHOW;

    switch(cmd.insnpref)
    {
    case SWFACTION_PUSH:
        {
            uint16 length = get_word(cmd.ea + 1) + 3; 
            uint16 p = cmd.auxpref;
            uint8 error = 0;
            while((length - p) > 0 && error == 0)
            {
                switch(get_byte(cmd.ea + p++))
                {
                case 0: //string
                    op.type = o_string;
                    op.dtyp = dt_string;
                    op.addr = cmd.ea + p;
                    //increment the pointer past the string
                    while((length - p) > 0 && get_byte(cmd.ea + p)){ p++; }
                    if ((length - p) > 0)
                    {
                        p++; //adjust for the null caracter
                    }
                    else
                    {
                        error = 1;
                    }
                    break;
                case 1: //float
                    op.type = o_imm;
                    //op.dtyp = dt_float;
                    op.dtyp = dt_dword;
                    if ((length - p) >= 4)
                    {
                        op.value = get_long(cmd.ea + p);
                        p += 4;
                    }
                    else
                    {
                        error = 1;
                    }
                    break;
                case 2: //null
                    op.type = o_null;
                    op.dtyp = dt_void;
                    break;
                case 3: //undefined
                    op.type = o_undefined;
                    op.dtyp = dt_void;
                    break;
                case 4: //register
                    op.type = o_reg;
                    op.dtyp = dt_byte;
                    if ((length - p) >= 1)
                    {
                        op.reg = get_byte(cmd.ea + p++);
                    }
                    else
                    {
                        error = 1;
                    }
                    break;
                case 5: //bool
                    op.type = o_bool;
                    op.dtyp = dt_byte;
                    if ((length - p) >= 1)
                    {
                        op.value = get_byte(cmd.ea + p++);
                    }
                    else
                    {
                        error = 1;
                    }
                    break;
                case 6: //double
                    op.type = o_imm;
                    op.dtyp = dt_double;
                    if ((length - p) >= 8)
                    {
                        double d = (double)(get_qword(cmd.ea + p));
                        op.value = d;
                        p += 8;
                    }
                    else
                    {
                        error = 1;
                    }
                    break;
                case 7: //integer
                    op.type = o_imm;
                    op.dtyp = dt_dword;
                    if ((length - p) >= 4)
                    {
                        op.value = get_long(cmd.ea + p);
                        p += 4;
                    }
                    else
                    {
                        error = 1;
                    }
                    break;
                case 8: //constant 8
                    op.type = o_const;
                    op.dtyp = dt_byte;
                    if ((length - p) >= 1)
                    {
                        op.value = get_byte(cmd.ea + p++);
                    }
                    else
                    {
                        error = 1;
                    }
                    break;
                case 9: //constant 16
                    op.type = o_const;
                    op.dtyp = dt_word;
                    if ((length - p) >= 2)
                    {
                        op.value = get_word(cmd.ea + p);
                        p += 2;
                    }
                    else
                    {
                        error = 1;
                    }
                default: //unknown type, will not search for more items if this happens
                    error = 1;
                } //switch
                if (error == 0)
                {
                    //pading
                    out_symbol( ',' );
                    OutChar( ' ' );
                    // output extra operand
                    outop(op);
                }
            } //while
        } //case
        break;
        case SWFACTION_TRY:
            //ToDo    
            break;
        case SWFACTION_DEFINEFUNCTION:
            // Todo: highlight somehow the function body
            // this must be written some other place because
            // every time IDA rephreshes the view a duplicate line appears. :(
            //describe(cmd.ea + cmd.size, true, "%s {", cmd.segpref ? (char*)cmd.Op1.addr : "<anonymous>");
            //describe(cmd.ea + cmd.size + get_word(cmd.ea + cmd.size - 2), true, " }");
            break;
    default:;
    }

    term_output_buffer();
    // attach a possible user-defined comment to this instruction
    gl_comm = 1;
    MakeLine( buf );

    //multiline instruction printing
    switch (cmd.insnpref)
    {
    case SWFACTION_CONSTANTPOOL:
        {    
            uint16 length = get_word(cmd.ea + 1);
            uint8 c = 0,
                count = 0;


            if(cmd.Op1.value == 0) 
                break;  

            //limit printed lines to 499
            //IDA does not suport more than 500 per item
            if (cmd.Op1.value > 498)
            {
                cmd.Op1.value = 498;
                msg ("\nWarning: CONSTANTPOOL instruction ar %X has more that 498 declared constants!\n", cmd.ea);
            }

            char line[MAXSTR], buf[MAXSTR];
            init_output_buffer(line, sizeof(line));

            OutChar( '    ' );
            out_char('0', COLOR_NUMBER);
            out_line(": \"",COLOR_SYMBOL);

            for (uint16 i = 2; i < length; i++)
            {
                c = get_byte(cmd.ea + i + 3);
                if (c == 0)
                {
                    if (count++ < (cmd.Op1.value - 1))
                    {
                        out_line("\"", COLOR_SYMBOL);
                        //terminate buffer for current constant
                        //and print it
                        term_output_buffer(); MakeLine(line);

                        //initialize buffer for next constant                        
                        init_output_buffer(line, sizeof(line));
                        
                        OutChar( '    ' );
                        qsnprintf(buf, MAXSTR, "%d", count);
                        out_line(buf, COLOR_NUMBER);
                        out_line(": \"", COLOR_SYMBOL);
                    }
                    else
                        break;
                }
                else
                {
                    if (is_printable(c))
                        out_char(c, COLOR_CHAR);
                    else
                    {
                        qsnprintf(buf, MAXSTR, "\\x%02X", c);
                        out_line(buf, COLOR_STRING);
                    }
                }//else
            }//for

            out_char('"',COLOR_SYMBOL);

            //terminate buffer for last constant
            //and print it
            term_output_buffer(); MakeLine(line);
        }
        break;
    }
}


bool __stdcall outop( op_t &x )
{
    char buf[MAXSTR];
    switch( x.type )
    {
    case o_imm:
        {
            switch(cmd.insnpref)
            {
            case SWFACTION_GETURL2:
                {
                    switch(x.specflag1)
                    {
                    case 'M':
                        if (x.value == 2)
                            out_keyword("method:POST");
                        else
                            x.value?out_keyword("method:GET"):out_keyword("method:none");
                        break;
                    case 'T':
                        x.value?out_keyword("target:sprite"):out_keyword("target:browser");
                        break;
                    case 'V':
                        x.value?out_keyword("vars:load"):out_keyword("vars:no");
                    }
                }
                break;
            case SWFACTION_CONSTANTPOOL:
                OutValue( x, OOFW_IMM );   
                break;
            case SWFACTION_GOTOFRAME2:
                if (x.n == 0)
                {
                    x.value?out_keyword("play:yes"):out_keyword("play:no");
                }
                else
                {
                    OutValue( x, OOFW_IMM );
                }
                break;
            case SWFACTION_DEFINEFUNCTION2:
                if (x.n == 5)
                {
                    //output the parameters first
                    uint16 p = cmd.auxpref,
                        i = 0;
                    uint16 param_length = get_word(cmd.ea + 1) - p -2;

                    out_char('{', COLOR_SYMBOL);
                    while (i < param_length)
                    {
                        
                        uint8 reg = get_byte(cmd.ea + 3 + p + i);
                        char* reg_name = buf;
                        *reg_name = 0;
                        
                        while ((i++ < param_length) && ((*(reg_name++) = get_byte(cmd.ea + 3 + p + i))!= 0)) {;}
                        i++;

                        if (reg_name > buf && *(--reg_name) == 0)
                        {
                            char r[6];
                            out_char('{', COLOR_SYMBOL);
                            if (reg)
                            {
                                qsnprintf(r, 5, "r%u", reg);
                                out_register( r );
                            }
                            else
                            {
                                out_char('0', COLOR_NUMBER);
                            }                            
                            out_line(",\"", COLOR_SYMBOL);
                            out_line(buf, COLOR_CHAR);
                            out_line("\"}, ", COLOR_SYMBOL);
                        }//if
                    }//while

                    out_line("}, ", COLOR_SYMBOL);
                }
                OutValue( x, OOFW_IMM );
                break;
            default:
                OutValue( x, OOFW_IMM );
            }
        }
        break;
    case o_reg:
        qsnprintf(buf, MAXSTR, "r%u", x.reg);
        out_register( buf );
        break;
    case o_near:
        if( !out_name_expr(x, x.addr, x.addr) ) 
        { 
            // if we could not create and output a name expression from the address
            OutValue(x, OOF_ADDR | OOF_NUMBER | OOFW_32); // instead output a raw value
            QueueMark(Q_noName, cmd.ea); //and mark this as a problem
        }
        break;
    case o_null:
        out_keyword("null");
        break;
    case o_undefined:
        out_keyword("undefined");
        break;
    case o_bool:
        x.value?out_keyword("true"):out_keyword("false");
        break;
    case o_const:
        out_keyword("constant:");
        OutValue( x, OOFW_IMM );
        break;
    case o_string:
        {
            uint16 p = 0;            
            char c;

            out_char('"', COLOR_SYMBOL);

            while ((c = get_byte(x.addr+p)) != 0)
            {
                if (is_printable(c))
                {
                    out_char(c, COLOR_CHAR);
                }
                else
                {
                    qsnprintf(buf, MAXSTR, "\\x%02X", c);
                    out_line(buf, COLOR_STRING);                    
                }
                p++;
            }

            out_char('"', COLOR_SYMBOL);
        }
        break;
    case o_void:
        return 0;
    default:
        warning( "out: %lx: bad optype %d", cmd.ea, x.type );
    }

    return 1;
}
