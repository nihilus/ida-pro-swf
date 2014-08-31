/*
*  Interactive disassembler (IDA).
*  Adobe Flash ActionScript2 processor module
*  Marian RADU <marianra@microsoft.com>
*/

#include "reg.hpp"
#include "out.hpp"
#include "ana.hpp"
#include "emu.hpp"
#include "ins.hpp"
#include "swf.hpp"

#define PLFM_SWF_AS2 0x8A54


enum SWF_AS2_regs
{
    r0 = 0,	r1, 	r2, 	r3, 	r4,
    r5,	    r6,	    r7,	    r8,	    r9,
    r10,	r11,	r12,	r13,	r14,
    r15,	r16,	r17,	r18,	r19,
    r20,	r21,	r22,	r23,	r24,
    r25,	r26,	r27,	r28,	r29,
    r30,	r31,	r32,	r33,	r34,
    r35,	r36,	r37,	r38,	r39,
    r40,	r41,	r42,	r43,	r44,
    r45,	r46,	r47,	r48,	r49,
    r50,	r51,	r52,	r53,	r54,
    r55,	r56,	r57,	r58,	r59,
    r60,	r61,	r62,	r63,	r64,
    r65,	r66,	r67,	r68,	r69,
    r70,	r71,	r72,	r73,	r74,
    r75,	r76,	r77,	r78,	r79,
    r80,	r81,	r82,	r83,	r84,
    r85,	r86,	r87,	r88,	r89,
    r90,	r91,	r92,	r93,	r94,
    r95,	r96,	r97,	r98,	r99,
    r100,	r101,	r102,	r103,	r104,
    r105,	r106,	r107,	r108,	r109,
    r110,	r111,	r112,	r113,	r114,
    r115,	r116,	r117,	r118,	r119,
    r120,	r121,	r122,	r123,	r124,
    r125,	r126,	r127,	r128,	r129,
    r130,	r131,	r132,	r133,	r134,
    r135,	r136,	r137,	r138,	r139,
    r140,	r141,	r142,	r143,	r144,
    r145,	r146,	r147,	r148,	r149,
    r150,	r151,	r152,	r153,	r154,
    r155,	r156,	r157,	r158,	r159,
    r160,	r161,	r162,	r163,	r164,
    r165,	r166,	r167,	r168,	r169,
    r170,	r171,	r172,	r173,	r174,
    r175,	r176,	r177,	r178,	r179,
    r180,	r181,	r182,	r183,	r184,
    r185,	r186,	r187,	r188,	r189,
    r190,	r191,	r192,	r193,	r194,
    r195,	r196,	r197,	r198,	r199,
    r200,	r201,	r202,	r203,	r204,
    r205,	r206,	r207,	r208,	r209,
    r210,	r211,	r212,	r213,	r214,
    r215,	r216,	r217,	r218,	r219,
    r220,	r221,	r222,	r223,	r224,
    r225,	r226,	r227,	r228,	r229,
    r230,	r231,	r232,	r233,	r234,
    r235,	r236,	r237,	r238,	r239,
    r240,	r241,	r242,	r243,	r244,
    r245,	r246,	r247,	r248,	r249,
    r250,	r251,	r252,	r253,	r254,
    r255,   rVcs,   rVds,   rEND
};
static int notify(processor_t::idp_notify msgid, ...)
{
  va_list va;
  va_start(va, msgid);

// A well behaving processor module should call invoke_callbacks()
// in his notify() function. If this function returns 0, then
// the processor module should process the notification itself
// Otherwise the code should be returned to the caller:


  int code = invoke_callbacks(HT_IDP, msgid, va);
  if ( code ) return code;

  switch(msgid)
  {
    case processor_t::init:
        //msg("processor_t::init notification called\n");
        inf.mf = 0;
        break;
    case processor_t::newfile:
        //msg("processor_t::newfile notification called\n");
        break;
    case processor_t::oldfile:
        //msg("processor_t::oldfile notification called\n");
        break;
    case processor_t::newprc:
        //msg("processor_t::newprc notification called\n");
        break;
    case processor_t::newseg:    // new segment
        //msg("processor_t::newseg notification called\n");
        break;
  }
  va_end(va);

  return(1);
}

static asm_t SWFAS2asm = {
  AS_COLON | ASH_HEXF0 | ASD_DECF0 | ASO_OCTF0 | ASB_BINF0 | AS_N2CHR | AS_ONEDUP,
  0,
  "SWF ActionScript 2 Assembler",
  0,
  NULL,
  NULL,
  ".org",
  ".end",

  ";",        // comment string
  '"',        // string delimiter
  '\'',       // char delimiter
  "'\"",      // special symbols in char and string constants

  ".db",      // ascii string directive
  ".db",      // byte directive
  ".dw",      // word directive
  ".dd",      // dwords
  ".dq",      // qwords
  NULL,       // oword  (16 bytes)
  NULL,       // float  (4 bytes)
  NULL,       // double (8 bytes)
  NULL,       // tbyte  (10/12 bytes)
  NULL,       // packed decimal real
  NULL,       // arrays (#h,#d,#v,#s(...)
  ".rs %s",   // uninited arrays
  ".equ",     // Equ
  NULL,       // seg prefix
  NULL,
  NULL,
  NULL,
  NULL,
  "*",
  NULL,		// func_header
  NULL,		// func_footer
  NULL,		// public
  NULL,		// weak
  NULL,		// extrn
  NULL,		// comm
  NULL,		// get_type_name
  NULL,		// align
  '(', ')',	// lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  NULL,    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};

static asm_t *asms[] = { &SWFAS2asm, NULL };
static char *shnames[] = { "SWF-AS2", NULL };
static char *lnames[]  = { "SWF ActionScript2", NULL };

static uchar retvl[] = { opcode_lookup[SWFACTION_RETURN] };    
static uchar retvd[] = { opcode_lookup[SWFACTION_END], opcode_lookup[SWFACTION_STOP]  };    
static bytes_t retcodes[] = {
    { sizeof( retvl ),  retvl },
    { sizeof( retvd ),  retvd },
    { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,        // version
  PLFM_SWF_AS2,                      // id
  PRN_HEX|PR_USE32,
  8,                            // 8 bits in a byte for code segments
  8,                            // 8 bits in a byte for other segments

  shnames,    // short processor names (null term)
  lnames,     // long processor names (null term)

  asms,       // array of enabled assemblers

  notify,     // Various messages:

  header,     // produce start of text file
  footer,     // produce end of text file

  segstart,   // produce start of segment
  segend,     // produce end of segment

  NULL,

  ana,
  emu,

  out,
  outop,
  intel_data,   
  NULL,       // compare operands
  NULL,       // can have type

  qnumber(SWF_AS2_regnames),                        // Number of registers
  SWF_AS2_regnames,                     // Register names
  NULL,                     // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  rVcs,rVds,
  0,                    // size of a segment register
  rVcs,rVds,

  NULL,                 // No known code start sequences
  retcodes,

  0, SWFACTION_LAST,
  Instructions,
  NULL,                 // int  (*is_far_jump)(int icode);
  NULL,                 // Translation function for offsets
  0,                    // int tbyte_size;  -- doesn't exist
  NULL,                 // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 0, 0, 0, 0 },       // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  NULL,                 // int (*is_switch)(switch_info_t *si);
  NULL,                 // int32 (*gen_map_file)(FILE *fp);
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  NULL,                 // int (*is_sp_based)(op_t &x); -- always, so leave it NULL
  NULL,                 // int (*create_func_frame)(func_t *pfn);
  NULL,                 // int (*get_frame_retsize(func_t *pfn)
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,int32 v);
  gen_spcdef,           // Generate text representation of an item in a special segment
};