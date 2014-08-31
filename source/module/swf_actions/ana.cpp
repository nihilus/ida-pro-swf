/*
*  Interactive disassembler (IDA).
*  Adobe Flash ActionScript2 processor module
*  Marian RADU <marianra@microsoft.com>
*/

#include "ana.hpp"
#include "ins.hpp"
#include "swf.hpp"

#define min(a,b) (((a) < (b)) ? (a) : (b))

uint16 instruction_lookup[] = 
{
    SWFACTION_END,              // 0x00 
    SWFACTION_NULL,             // 0x01 
    SWFACTION_NULL,             // 0x02 
    SWFACTION_NULL,             // 0x03 
    SWFACTION_NEXTFRAME,        // 0x04 
    SWFACTION_PREVFRAME,        // 0x05 
    SWFACTION_PLAY,             // 0x06 
    SWFACTION_STOP,             // 0x07 
    SWFACTION_TOGGLEQUALITY,    // 0x08 
    SWFACTION_STOPSOUNDS,       // 0x09 
    SWFACTION_ADD,              // 0x0A 
    SWFACTION_SUBTRACT,         // 0x0B 
    SWFACTION_MULTIPLY,         // 0x0C 
    SWFACTION_DIVIDE,           // 0x0D 
    SWFACTION_EQUALS,           // 0x0E 
    SWFACTION_LESSTHAN,         // 0x0F 
    SWFACTION_AND,              // 0x10 
    SWFACTION_OR,               // 0x11 
    SWFACTION_NOT,              // 0x12 
    SWFACTION_STRINGEQ,         // 0x13 
    SWFACTION_STRINGLENGTH,     // 0x14 
    SWFACTION_STRINGEXTRACT,    // 0x15 
    SWFACTION_NULL,             // 0x16 
    SWFACTION_POP,              // 0x17 
    SWFACTION_TOINT,            // 0x18 
    SWFACTION_NULL,             // 0x19 
    SWFACTION_NULL,             // 0x1A 
    SWFACTION_NULL,             // 0x1B 
    SWFACTION_GETVARIABLE,      // 0x1C 
    SWFACTION_SETVARIABLE,      // 0x1D 
    SWFACTION_NULL,             // 0x1E 
    SWFACTION_NULL,             // 0x1F 
    SWFACTION_SETTARGET2,       // 0x20 
    SWFACTION_STRINGCONCAT,     // 0x21 
    SWFACTION_GETPROPERTY,      // 0x22 
    SWFACTION_SETPROPERTY,      // 0x23 
    SWFACTION_CLONESPRITE,      // 0x24 
    SWFACTION_REMOVESPRITE,     // 0x25 
    SWFACTION_TRACE,            // 0x26 
    SWFACTION_STARTDRAGMOVIE,   // 0x27 
    SWFACTION_STOPDRAGMOVIE,    // 0x28 
    SWFACTION_STRINGLESSTHAN,   // 0x29 
    SWFACTION_THROW,            // 0x2A 
    SWFACTION_CAST,             // 0x2B 
    SWFACTION_IMPLEMENTS,       // 0x2C 
    SWFACTION_FSCOMMAND2,       // 0x2D 
    SWFACTION_NULL,             // 0x2E 
    SWFACTION_NULL,             // 0x2F 
    SWFACTION_RANDOM,           // 0x30 
    SWFACTION_MBSTRINGLENGTH,   // 0x31 
    SWFACTION_CHARTOASCII,      // 0x32 
    SWFACTION_ASCIITOCAHR,      // 0x33 
    SWFACTION_GETTIMER,         // 0x34 
    SWFACTION_MBSTRINGEXTRACT,  // 0x35 
    SWFACTION_MBCHARTOASCII,    // 0x36 
    SWFACTION_MBASCIITOCHAR,    // 0x37 
    SWFACTION_NULL,             // 0x38 
    SWFACTION_NULL,             // 0x39 
    SWFACTION_DELETE,           // 0x3A 
    SWFACTION_DELETE2,          // 0x3B 
    SWFACTION_DEFINELOCAL,      // 0x3C 
    SWFACTION_CALL,             // 0x3D 
    SWFACTION_RETURN,           // 0x3E 
    SWFACTION_MODULO,           // 0x3F 
    SWFACTION_NEWOBJECT,        // 0x40 
    SWFACTION_VAR,              // 0x41 
    SWFACTION_INITARRAY,        // 0x42 
    SWFACTION_INITOBJECT,       // 0x43 
    SWFACTION_TYPEOF,           // 0x44 
    SWFACTION_TARGETPATH,       // 0x45 
    SWFACTION_ENUMERATE,        // 0x46 
    SWFACTION_ADD2,             // 0x47 
    SWFACTION_LESS2,            // 0x48 
    SWFACTION_EQUALS2,          // 0x49 
    SWFACTION_TONUMBER,         // 0x4A 
    SWFACTION_TOSTRING,         // 0x4B 
    SWFACTION_PUSHDUPLICATE,    // 0x4C 
    SWFACTION_STACKSWAP,        // 0x4D 
    SWFACTION_GETMEMBER,        // 0x4E 
    SWFACTION_SETMEMBER,        // 0x4F 
    SWFACTION_INCREMENT,        // 0x50 
    SWFACTION_DECREMENT,        // 0x51 
    SWFACTION_CALLMETHOD,       // 0x52 
    SWFACTION_NEWMETHOD,        // 0x53 
    SWFACTION_INSTANCEOF,       // 0x54 
    SWFACTION_ENUMERATE2,       // 0x55 
    SWFACTION_NULL,             // 0x56 
    SWFACTION_NULL,             // 0x57 
    SWFACTION_NULL,             // 0x58 
    SWFACTION_NULL,             // 0x59 
    SWFACTION_NULL,             // 0x5A 
    SWFACTION_NULL,             // 0x5B 
    SWFACTION_NULL,             // 0x5C 
    SWFACTION_NULL,             // 0x5D 
    SWFACTION_NULL,             // 0x5E 
    SWFACTION_NULL,             // 0x5F 
    SWFACTION_BITWISEAND,       // 0x60 
    SWFACTION_BITWISEOR,        // 0x61 
    SWFACTION_BITWISEXOR,       // 0x62 
    SWFACTION_SHIFTLEFT,        // 0x63 
    SWFACTION_SHIFTRIGHT,       // 0x64 
    SWFACTION_SHIFTRIGHT2,      // 0x65 
    SWFACTION_STRICTEQUALS,     // 0x66 
    SWFACTION_GREATER,          // 0x67 
    SWFACTION_STRINGGREATER,    // 0x68 
    SWFACTION_EXTENDS,          // 0x69 
    SWFACTION_NULL,             // 0x6A 
    SWFACTION_NULL,             // 0x6B 
    SWFACTION_NULL,             // 0x6C 
    SWFACTION_NULL,             // 0x6D 
    SWFACTION_NULL,             // 0x6E 
    SWFACTION_NULL,             // 0x6F 
    SWFACTION_NULL,             // 0x70 
    SWFACTION_NULL,             // 0x71 
    SWFACTION_NULL,             // 0x72 
    SWFACTION_NULL,             // 0x73 
    SWFACTION_NULL,             // 0x74 
    SWFACTION_NULL,             // 0x75 
    SWFACTION_NULL,             // 0x76 
    SWFACTION_NULL,             // 0x77 
    SWFACTION_NULL,             // 0x78 
    SWFACTION_NULL,             // 0x79 
    SWFACTION_NULL,             // 0x7A 
    SWFACTION_NULL,             // 0x7B 
    SWFACTION_NULL,             // 0x7C 
    SWFACTION_NULL,             // 0x7D 
    SWFACTION_NULL,             // 0x7E 
    SWFACTION_NULL,             // 0x7F 
    SWFACTION_NULL,             // 0x80
    SWFACTION_GOTOFRAME,        // 0x81 
    SWFACTION_NULL,             // 0x82 
    SWFACTION_GETURL,           // 0x83 
    SWFACTION_NULL,             // 0x84 
    SWFACTION_NULL,             // 0x85 
    SWFACTION_NULL,             // 0x86 
    SWFACTION_STOREREGISTER,    // 0x87 
    SWFACTION_CONSTANTPOOL,     // 0x88 
    SWFACTION_STRICTMODE,       // 0x89 
    SWFACTION_WAITFORFRAME,     // 0x8A 
    SWFACTION_SETTARGET,        // 0x8B 
    SWFACTION_GOTOLABEL,        // 0x8C 
    SWFACTION_WAITFORFRAME2,    // 0x8D 
    SWFACTION_DEFINEFUNCTION2,  // 0x8E 
    SWFACTION_TRY,              // 0x8F 
    SWFACTION_NULL,             // 0x90 
    SWFACTION_NULL,             // 0x91 
    SWFACTION_NULL,             // 0x92 
    SWFACTION_NULL,             // 0x93 
    SWFACTION_WITH,             // 0x94 
    SWFACTION_NULL,             // 0x95 
    SWFACTION_PUSH,             // 0x96 
    SWFACTION_NULL,             // 0x97 
    SWFACTION_NULL,             // 0x98 
    SWFACTION_JUMP,             // 0x99 
    SWFACTION_GETURL2,          // 0x9A 
    SWFACTION_DEFINEFUNCTION,   // 0x9B 
    SWFACTION_NULL,             // 0x9C 
    SWFACTION_BRANCHIFTRUE,     // 0x9D 
    SWFACTION_CALLFRAME,        // 0x9E 
    SWFACTION_GOTOFRAME2,       // 0x9F 
    SWFACTION_NULL,             // 0xA0 
    SWFACTION_NULL,             // 0xA1 
    SWFACTION_NULL,             // 0xA2 
    SWFACTION_NULL,             // 0xA3 
    SWFACTION_NULL,             // 0xA4 
    SWFACTION_NULL,             // 0xA5 
    SWFACTION_NULL,             // 0xA6 
    SWFACTION_NULL,             // 0xA7 
    SWFACTION_NULL,             // 0xA8 
    SWFACTION_NULL,             // 0xA9 
    SWFACTION_NULL,             // 0xAA 
    SWFACTION_NULL,             // 0xAB 
    SWFACTION_NULL,             // 0xAC 
    SWFACTION_NULL,             // 0xAD 
    SWFACTION_NULL,             // 0xAE 
    SWFACTION_NULL,             // 0xAF 
    SWFACTION_NULL,             // 0xB0 
    SWFACTION_NULL,             // 0xB1 
    SWFACTION_NULL,             // 0xB2 
    SWFACTION_NULL,             // 0xB3 
    SWFACTION_NULL,             // 0xB4 
    SWFACTION_NULL,             // 0xB5 
    SWFACTION_NULL,             // 0xB6 
    SWFACTION_NULL,             // 0xB7 
    SWFACTION_NULL,             // 0xB8 
    SWFACTION_NULL,             // 0xB9 
    SWFACTION_NULL,             // 0xBA 
    SWFACTION_NULL,             // 0xBB 
    SWFACTION_NULL,             // 0xBC 
    SWFACTION_NULL,             // 0xBD 
    SWFACTION_NULL,             // 0xBE 
    SWFACTION_NULL,             // 0xBF 
    SWFACTION_NULL,             // 0xC0 
    SWFACTION_NULL,             // 0xC1 
    SWFACTION_NULL,             // 0xC2 
    SWFACTION_NULL,             // 0xC3 
    SWFACTION_NULL,             // 0xC4 
    SWFACTION_NULL,             // 0xC5 
    SWFACTION_NULL,             // 0xC6 
    SWFACTION_NULL,             // 0xC7 
    SWFACTION_NULL,             // 0xC8 
    SWFACTION_NULL,             // 0xC9 
    SWFACTION_NULL,             // 0xCA 
    SWFACTION_NULL,             // 0xCB 
    SWFACTION_NULL,             // 0xCC 
    SWFACTION_NULL,             // 0xCD 
    SWFACTION_NULL,             // 0xCE 
    SWFACTION_NULL,             // 0xCF 
    SWFACTION_NULL,             // 0xD0 
    SWFACTION_NULL,             // 0xD1 
    SWFACTION_NULL,             // 0xD2 
    SWFACTION_NULL,             // 0xD3 
    SWFACTION_NULL,             // 0xD4 
    SWFACTION_NULL,             // 0xD5 
    SWFACTION_NULL,             // 0xD6 
    SWFACTION_NULL,             // 0xD7 
    SWFACTION_NULL,             // 0xD8 
    SWFACTION_NULL,             // 0xD9 
    SWFACTION_NULL,             // 0xDA 
    SWFACTION_NULL,             // 0xDB 
    SWFACTION_NULL,             // 0xDC 
    SWFACTION_NULL,             // 0xDD 
    SWFACTION_NULL,             // 0xDE 
    SWFACTION_NULL,             // 0xDF 
    SWFACTION_NULL,             // 0xE0 
    SWFACTION_NULL,             // 0xE1 
    SWFACTION_NULL,             // 0xE2 
    SWFACTION_NULL,             // 0xE3 
    SWFACTION_NULL,             // 0xE4 
    SWFACTION_NULL,             // 0xE5 
    SWFACTION_NULL,             // 0xE6 
    SWFACTION_NULL,             // 0xE7 
    SWFACTION_NULL,             // 0xE8 
    SWFACTION_NULL,             // 0xE9 
    SWFACTION_NULL,             // 0xEA 
    SWFACTION_NULL,             // 0xEB 
    SWFACTION_NULL,             // 0xEC 
    SWFACTION_NULL,             // 0xED 
    SWFACTION_NULL,             // 0xEE 
    SWFACTION_NULL,             // 0xEF 
    SWFACTION_NULL,             // 0xF0 
    SWFACTION_NULL,             // 0xF1 
    SWFACTION_NULL,             // 0xF2 
    SWFACTION_NULL,             // 0xF3 
    SWFACTION_NULL,             // 0xF4 
    SWFACTION_NULL,             // 0xF5 
    SWFACTION_NULL,             // 0xF6 
    SWFACTION_NULL,             // 0xF7 
    SWFACTION_NULL,             // 0xF8 
    SWFACTION_NULL,             // 0xF9 
    SWFACTION_NULL,             // 0xFA 
    SWFACTION_NULL,             // 0xFB 
    SWFACTION_NULL,             // 0xFC 
    SWFACTION_NULL,             // 0xFD 
    SWFACTION_NULL,             // 0xFE 
    SWFACTION_NULL              // 0xFF 
};

uint8 opcode_lookup[] = 
{
    0x00,  //SWFACTION_NULL
    0x00,  //SWFACTION_END
    0x04,  //SWFACTION_NEXTFRAME
    0x05,  //SWFACTION_PREVFRAME
    0x06,  //SWFACTION_PLAY
    0x07,  //SWFACTION_STOP
    0x08,  //SWFACTION_TOGGLEQUALITY
    0x09,  //SWFACTION_STOPSOUNDS
    0x81,  //SWFACTION_GOTOFRAME
    0x83,  //SWFACTION_GETURL
    0x8A,  //SWFACTION_WAITFORFRAME
    0x8B,  //SWFACTION_SETTARGET
    0x8C,  //SWFACTION_GOTOLABEL
    0x0A,  //SWFACTION_ADD
    0x0B,  //SWFACTION_SUBTRACT
    0x0C,  //SWFACTION_MULTIPLY
    0x0D,  //SWFACTION_DIVIDE
    0x0E,  //SWFACTION_EQUALS
    0x0F,  //SWFACTION_LESSTHAN
    0x10,  //SWFACTION_AND
    0x11,  //SWFACTION_OR
    0x12,  //SWFACTION_NOT
    0x13,  //SWFACTION_STRINGEQ
    0x14,  //SWFACTION_STRINGLENGTH
    0x15,  //SWFACTION_STRINGEXTRACT
    0x17,  //SWFACTION_POP
    0x18,  //SWFACTION_TOINT
    0x1C,  //SWFACTION_GETVARIABLE
    0x1D,  //SWFACTION_SETVARIABLE
    0x20,  //SWFACTION_SETTARGET2
    0x21,  //SWFACTION_STRINGCONCAT
    0x22,  //SWFACTION_GETPROPERTY
    0x23,  //SWFACTION_SETPROPERTY
    0x24,  //SWFACTION_CLONESPRITE
    0x25,  //SWFACTION_REMOVESPRITE
    0x26,  //SWFACTION_TRACE
    0x27,  //SWFACTION_STARTDRAGMOVIE
    0x28,  //SWFACTION_STOPDRAGMOVIE
    0x29,  //SWFACTION_STRINGLESSTHAN
    0x30,  //SWFACTION_RANDOM
    0x31,  //SWFACTION_MBSTRINGLENGTH
    0x32,  //SWFACTION_CHARTOASCII
    0x33,  //SWFACTION_ASCIITOCAHR
    0x34,  //SWFACTION_GETTIMER
    0x35,  //SWFACTION_MBSTRINGEXTRACT
    0x36,  //SWFACTION_MBCHARTOASCII
    0x37,  //SWFACTION_MBASCIITOCHAR
    0x8D,  //SWFACTION_WAITFORFRAME2
    0x96,  //SWFACTION_PUSH
    0x99,  //SWFACTION_JUMP
    0x9A,  //SWFACTION_GETURL2
    0x9D,  //SWFACTION_BRANCHIFTRUE
    0x9E,  //SWFACTION_CALLFRAME
    0x9F,  //SWFACTION_GOTOFRAME2
    0x3A,  //SWFACTION_DELETE
    0x3B,  //SWFACTION_DELETE2
    0x3C,  //SWFACTION_DEFINELOCAL
    0x3D,  //SWFACTION_CALL
    0x3E,  //SWFACTION_RETURN
    0x3F,  //SWFACTION_MODULO
    0x40,  //SWFACTION_NEWOBJECT
    0x41,  //SWFACTION_VAR
    0x42,  //SWFACTION_INITARRAY
    0x43,  //SWFACTION_INITOBJECT
    0x44,  //SWFACTION_TYPEOF
    0x45,  //SWFACTION_TARGETPATH
    0x46,  //SWFACTION_ENUMERATE
    0x47,  //SWFACTION_ADD2
    0x48,  //SWFACTION_LESS2
    0x49,  //SWFACTION_EQUALS2
    0x4A,  //SWFACTION_TONUMBER
    0x4B,  //SWFACTION_TOSTRING
    0x4C,  //SWFACTION_PUSHDUPLICATE
    0x4D,  //SWFACTION_STACKSWAP
    0x4E,  //SWFACTION_GETMEMBER
    0x4F,  //SWFACTION_SETMEMBER
    0x50,  //SWFACTION_INCREMENT
    0x51,  //SWFACTION_DECREMENT
    0x52,  //SWFACTION_CALLMETHOD
    0x53,  //SWFACTION_NEWMETHOD
    0x60,  //SWFACTION_BITWISEAND
    0x61,  //SWFACTION_BITWISEOR
    0x62,  //SWFACTION_BITWISEXOR
    0x63,  //SWFACTION_SHIFTLEFT
    0x64,  //SWFACTION_SHIFTRIGHT
    0x65,  //SWFACTION_SHIFTRIGHT2
    0x87,  //SWFACTION_STOREREGISTER
    0x88,  //SWFACTION_CONSTANTPOOL
    0x94,  //SWFACTION_WITH
    0x9B,  //SWFACTION_DEFINEFUNCTION
    0x54,  //SWFACTION_INSTANCEOF
    0x55,  //SWFACTION_ENUMERATE2
    0x66,  //SWFACTION_STRICTEQUALS
    0x67,  //SWFACTION_GREATER
    0x68,  //SWFACTION_STRINGGREATER
    0x89,  //SWFACTION_STRICTMODE
    0x2B,  //SWFACTION_CAST
    0x2C,  //SWFACTION_IMPLEMENTS
    0x69,  //SWFACTION_EXTENDS
    0x8E,  //SWFACTION_DEFINEFUNCTION2
    0x8F,  //SWFACTION_TRY
    0x2A,  //SWFACTION_THROW
    0x2D,  //SWFACTION_FSCOMMAND2
    0x00   //SWFACTION_LAST
};

int __stdcall ana(void) {
    uint8 byte = ua_next_byte();

    cmd.itype = instruction_lookup[byte];

    if ((byte < 0x80) || (cmd.itype == SWFACTION_NULL))
    {
        switch(cmd.itype)
        {
        case SWFACTION_NULL:
            cmd.size = 0;
            break;
        default:
            cmd.size = 1;
        }
    }
    else
    {
        uint16 length = ua_next_word();

        if (length != 0)
        {
            switch(cmd.itype)
            {
            case SWFACTION_WAITFORFRAME2:
                cmd.Op1.type = o_imm;
                cmd.Op1.dtyp = dt_byte;
                cmd.Op1.value = ua_next_byte();
                break;
            case SWFACTION_GOTOFRAME:
                cmd.Op1.type = o_imm;
                cmd.Op1.dtyp = dt_word;
                cmd.Op1.value = ua_next_word();
                //length is always 2
                length = 2;
                break;
            case SWFACTION_WITH:
                cmd.Op1.type = o_imm;
                cmd.Op1.dtyp = dt_word;
                cmd.Op1.value = ua_next_word();
                break;
            case SWFACTION_SETTARGET:
            case SWFACTION_GOTOLABEL:
                cmd.Op1.type = o_string;
                cmd.Op1.dtyp = dt_string;
                cmd.Op1.addr = cmd.ea + 3;
                break;
            case SWFACTION_PUSH:
                {
                    uint8 i = 0, 
                        error = 0;
                    uint16 items = 0,
                        p = 0;

                    do
                    {   
                        p++; // pre increment, for the following byte read
                        switch(ua_next_byte())
                        {
                        case 0: // string literal
                            cmd.Operands[i].type = o_string;
                            cmd.Operands[i].dtyp = dt_string;
                            cmd.Operands[i].addr = cmd.ea + 3 + p;
                            //increment the pointer past the string
                            while((length - p) > 0 && ua_next_byte()){ p++; }
                            if ((length - p) > 0)
                            {
                                p++; //adjust for the null caracter
                            }
                            else
                            {
                                error = 1;
                            }
                            break;        
                        case 1: // floating-point literal
                            cmd.Operands[i].type = o_imm;
                            //cmd.Operands[i].dtyp = dt_float;
                            cmd.Operands[i].dtyp = dt_dword;
                            if ((length - p) >= 4)
                            {
                                cmd.Operands[i].value = ua_next_long();
                                p += 4;
                            }
                            else
                            {
                                error = 1;
                            }
                            break;
                        case 2: // null
                            cmd.Operands[i].type = o_null;
                            cmd.Operands[i].dtyp = dt_void;
                            break;
                        case 3: // undefined
                            cmd.Operands[i].type = o_undefined;
                            cmd.Operands[i].dtyp = dt_void;
                            break;
                        case 4: // register
                            cmd.Operands[i].type = o_reg;
                            cmd.Operands[i].dtyp = dt_byte;
                            if ((length - p) >= 1)
                            {
                                cmd.Operands[i].reg = ua_next_byte();
                                p++;
                            }
                            else
                            {
                                error = 1;
                            }
                            break;
                        case 5: // boolean
                            cmd.Operands[i].type = o_bool;
                            cmd.Operands[i].dtyp = dt_byte;
                            if ((length - p) >= 1)
                            {
                                cmd.Operands[i].value = ua_next_byte();
                                p++;
                            }
                            else
                            {
                                error = 1;
                            }
                            break;
                        case 6: // double
                            cmd.Operands[i].type = o_imm;
                            cmd.Operands[i].dtyp = dt_double;
                            if ((length - p) >= 8)
                            {
                                double d = (double)(ua_next_qword());
                                cmd.Operands[i].value = d;
                                p += 8;
                            }
                            else
                            {
                                error = 1;
                            }
                            break;
                        case 7: // integer
                            cmd.Operands[i].type = o_imm;
                            cmd.Operands[i].dtyp = dt_dword;
                            if ((length - p) >= 4)
                            {
                                cmd.Operands[i].value = ua_next_long();
                                p += 4;
                            }
                            else
                            {
                                error = 1;
                            }
                            break;
                        case 8: // constant8
                            cmd.Operands[i].type = o_const;
                            cmd.Operands[i].dtyp = dt_byte;
                            if ((length - p) >= 1)
                            {
                                cmd.Operands[i].value = ua_next_byte();
                                p++;
                            }
                            else
                            {
                                error = 1;
                            }
                            break;
                        case 9: // constant16
                            cmd.Operands[i].type = o_const;
                            cmd.Operands[i].dtyp = dt_word;
                            if ((length - p) >= 2)
                            {
                                cmd.Operands[i].value = ua_next_word();
                                p += 2;
                            }
                            else
                            {
                                error = 1;
                            }
                            break;
                        default: //unknown type, will not search for more items if this happens
                            error = 1;
                        }//switch
                        if (error == 0) 
                            items++;
                        else
                            break;
                    }//do
                    while (i++ < min(UA_MAXOP-1, items) && (length - p) > 0);

                    if (error != 0)
                    {
                        //there was an error in extracting the last operand
                        cmd.Operands[i].type = o_void;
                    }
                    else if ( (items >= UA_MAXOP))
                    {
                        // more values may be pushed but we'll handle those at output level
                        // store the ea_t pointer of the unprocessed items in auxpref
                        cmd.auxpref = p + 3; 
                        cmd.insnpref = SWFACTION_PUSH;
                    }
                }//case
                break;
                case SWFACTION_JUMP:
                case SWFACTION_BRANCHIFTRUE:
                    cmd.Op1.type = o_near;                    
                    cmd.Op1.addr = cmd.ea + (int16)ua_next_word() + 3 + length;
                    break;
                case SWFACTION_GETURL:
                    {
                        uint16 p = 0;
                        cmd.Op1.type = o_string;
                        cmd.Op1.dtyp = dt_string;
                        cmd.Op1.addr = cmd.ea + 3;
                        //increment the pointer past the string
                        while((length - p) > 0 && ua_next_byte())
                            p++;
                        if ((length - p) > 0)
                        {
                            p++; //adjust for the null caracter
                        }
                        else
                        {
                            //error
                            cmd.Op1.type = o_void;
                            break;
                        }
                        cmd.Op2.type = o_string;
                        cmd.Op2.dtyp = dt_string;
                        cmd.Op2.addr = cmd.ea + 3 + p;
                        //check the presence of a valid null terminated string
                        while((length - p) > 0 && ua_next_byte())
                            p++;
                        if ((length - p) > 0)
                        {
                            p++; //adjust for the null caracter
                        }
                        else
                        {
                            //error
                            cmd.Op2.type = o_void;
                        }
                    }
                    break;
                case SWFACTION_STOREREGISTER:
                    cmd.Op1.type = o_reg;
                    cmd.Op1.dtyp = dt_byte;
                    cmd.Op1.reg = ua_next_byte();
                    break;
                case SWFACTION_WAITFORFRAME:
                    cmd.Op1.type = o_imm;
                    cmd.Op1.dtyp = dt_word;
                    cmd.Op1.value = ua_next_word();
                    cmd.Op2.type = o_imm;
                    cmd.Op2.dtyp = dt_byte;
                    cmd.Op2.value = ua_next_byte();
                    //length is always 3
                    length = 3;
                    break;
                case SWFACTION_GETURL2:
                    {
                        uint8 flags = ua_next_byte();
                        cmd.Op1.type = cmd.Op2.type = cmd.Op3.type = o_imm;
                        cmd.Op1.dtyp = cmd.Op2.dtyp = cmd.Op3.dtyp = dt_byte;
                        cmd.Op1.value = flags >> 6;
                        cmd.Op2.value = (flags & 3) >> 1;
                        cmd.Op3.value = flags & 1;
                        cmd.Op1.specflag1 = 'M';
                        cmd.Op2.specflag1 = 'T';
                        cmd.Op3.specflag1 = 'V';
                        cmd.insnpref = SWFACTION_GETURL2;
                        //length is always 1
                        length = 1;
                    }
                    break;
                case SWFACTION_GOTOFRAME2:
                    {
                        uint8 flags = ua_next_byte();
                        //play flag
                        cmd.Op1.type = o_imm;
                        cmd.Op1.dtyp = dt_byte;
                        cmd.Op1.value = flags & 1;
                        //scene bias
                        if (((flags & 3) >> 1) && (length == 3))
                        {
                            cmd.Op2.type = o_imm;
                            cmd.Op2.dtyp = dt_word;
                            cmd.Op2.value = ua_next_word();
                        } 
                        cmd.insnpref = SWFACTION_GOTOFRAME2;
                    }
                    break;
                case SWFACTION_DEFINEFUNCTION2:
                    {
                        uint16 p = 0;
                        // function name
                        cmd.Op1.type = o_string;
                        cmd.Op1.dtyp = dt_string;
                        cmd.Op1.addr = cmd.ea + 3;
                        //increment the pointer past the string
                        while((length - p) > 0 && ua_next_byte())
                            p++;
                        if ((length - p) > 0)
                        {
                            p++; //adjust for the null caracter
                        }
                        else
                        {
                            //error
                            cmd.Op1.type = o_void;
                            break;
                        }
                        //NumParams
                        if ((length - p) >= 2)
                        {
                            cmd.Op2.type = o_imm;
                            cmd.Op2.dtyp = dt_word;
                            cmd.Op2.value = ua_next_word();
                            p += 2;
                        }
                        else
                        {
                            //error
                            cmd.Op2.type = o_void;
                            break;
                        }
                        //Register count
                        if ((length - p) >= 1)
                        {
                            cmd.Op3.type = o_imm;
                            cmd.Op3.dtyp = dt_byte;
                            cmd.Op3.value = ua_next_byte();
                            p ++;
                        }
                        else
                        {
                            //error
                            cmd.Op3.type = o_void;
                            break;
                        }
                        //flags1
                        if ((length - p) >= 1)
                        {
                            cmd.Op4.type = o_imm;
                            cmd.Op4.dtyp = dt_byte;
                            cmd.Op4.value = ua_next_byte();
                            p ++;
                        }
                        else
                        {
                            //error
                            cmd.Op4.type = o_void;
                            break;
                        }
                        //PreloadGlobalFlag
                        if ((length - p) >= 1)
                        {
                            cmd.Op5.type = o_imm;
                            cmd.Op5.dtyp = dt_byte;
                            cmd.Op5.value = ua_next_byte() & 1;
                            p ++;
                        }
                        else
                        {
                            //error
                            cmd.Op5.type = o_void;
                            break;
                        }
                        //Parameters
                        //skip it, will process&output at output step
                        //save processing pointer
                        cmd.auxpref = p;

                        //Length
                        cmd.Op6.type = o_imm;
                        cmd.Op6.dtyp = dt_word;
                        //usually we chech if tehre is enough data but 
                        //this si a special case, at least for now
                        cmd.Op6.value = get_word(cmd.ea + length + 1);
                        
                        cmd.insnpref = SWFACTION_DEFINEFUNCTION2;
                    }//case
                    break;
                case SWFACTION_CONSTANTPOOL:
                    //only set one operand, the number of defined constants
                    cmd.Op1.type = o_imm;
                    cmd.Op1.dtyp = dt_word;
                    cmd.Op1.value = ua_next_word();  
                    //data used in outputing the insn
                    cmd.insnpref = SWFACTION_CONSTANTPOOL;
                    break;
                case SWFACTION_DEFINEFUNCTION:
                    {
                        uint16 p = 0;

                        //fucntion name
                        cmd.Op1.type = o_string;
                        cmd.Op1.dtyp = dt_string;
                        cmd.Op1.addr = cmd.ea + 3;
                        //increment the pointer past the string
                        while((length - p) > 0 && ua_next_byte())
                            p++;
                        if ((length - p) > 0)
                        {
                            p++; //adjust for the null caracter
                            //use segpref as an indicator for anonymous function
                            p == 1 ? cmd.segpref = 1 : cmd.segpref = 0;
                        }
                        else
                        {
                            //error
                            cmd.Op1.type = o_void;
                            break;
                        }

                        if ((length - p) >= 2)
                        {
                            cmd.Op2.type = o_imm;
                            cmd.Op2.dtyp = dt_word;
                            cmd.Op2.value = ua_next_word();
                            p += 2;
                        }
                        else
                        {
                            //error
                            cmd.Op2.type = o_void;
                            break;
                        }
                        
                        cmd.Op3.type = o_imm;
                        cmd.Op3.dtyp = dt_word;
                        cmd.Op3.value = get_word(cmd.ea + length + 1);

                        cmd.auxpref = p;
                        cmd.insnpref = SWFACTION_DEFINEFUNCTION;
                    }
                    break;
                case SWFACTION_TRY:
                    {   
                        uint16 p = 0;
                        //flags
                        cmd.Op1.type = o_imm;
                        cmd.Op1.dtyp = dt_byte;
                        cmd.Op1.value = ua_next_byte();
                        p++;
                        //Try size
                        if ((length - p) >= 2)
                        {
                            cmd.Op2.type = o_imm;
                            cmd.Op2.dtyp = dt_word;
                            cmd.Op2.value = ua_next_word();
                            p+=2;
                        }
                        else
                        {
                            //error
                            cmd.Op2.type = o_void;
                            break;
                        }
                        //Catch size
                        if ((length - p) >= 2)
                        {
                            cmd.Op3.type = o_imm;
                            cmd.Op3.dtyp = dt_word;
                            cmd.Op3.value = ua_next_word();
                            p+=2;
                        }
                        else
                        {
                            //error
                            cmd.Op3.type = o_void;
                            break;
                        }
                        //Finnaly size
                        if ((length - p) >= 2)
                        {
                            cmd.Op4.type = o_imm;
                            cmd.Op4.dtyp = dt_word;
                            cmd.Op4.value = ua_next_word();
                            p+=2;
                        }
                        else
                        {
                            //error
                            cmd.Op4.type = o_void;
                            break;
                        }
                        cmd.auxpref = p;
                        cmd.insnpref = SWFACTION_TRY;
                    }
                    break;
            }//switch
        }//if
        cmd.size = 3 + length;
    }//else

    return cmd.size;
}
