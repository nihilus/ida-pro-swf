/*
*  Interactive disassembler (IDA).
*  LOADER for Adobe Flash Files
*  Marian RADU <marianra@microsoft.com>
*/

#include <idaldr.h>

#ifndef __SWFSTRUCTS_HPP
#define __SWFSTRUCTS_HPP

typedef struct _SWFRECT {
    int32   Xmin;
    int32   Xmax;
    int32   Ymin;
    int32   Ymax;
} SWFRECT;

typedef struct _SWFMATRIX {
    int32   scaleX;
    int32   scaleY;
    int32   rotateSkew0;
    int32   rotateSkew1;
    int32   translateX;
    int32   translateY;
} SWFMATRIX;

typedef struct _SWFCXFORMWITHALPHA {
    int32 redMultTerm;
    int32 greenMultTerm;
    int32 blueMultTerm;
    int32 alphaMultTerm;
    int32 redAddTerm;
    int32 greenAddTerm;
    int32 blueAddTerm;
    int32 alphaAddTerm;
} SWFCXFORMWITHALPHA;

typedef enum _SWFFILTERID {
    DROPSHADOWFILTER    = 0,
    BLURFILTER          = 1,
    GLOWFILTER          = 2,
    BEVELFILTER         = 3,
    GRADIENTGLOWFILTER  = 4,
    CONVOLUTIONFILTER   = 5,
    COLORMATRIXFILTER   = 6,
    GRADIENTBEVELFILTER = 7,
} SWFFILTERID;

// Transform PlaceObject event value into
// a descriptive name that can be used as 
// entry point function name.
void event2string(uint32 event, char *name, int len);

// Transform DefineButton event value into
// a descriptive name that can be used as 
// entry point function name.
void buttonevent2string(uint16 event, char *name, int len);

// Read "lenght" amount of bits from offset 
// "bitoffset" from the byte at the current
// read pointer.
// Read pointer will be mover by bitOffset%8 + 1 bytes
uint32 read_bits(linput_t *li, uint8 bitOffset, uint8 lenght);

// Read and fill A SWFRECT structure from the
// current read pointer.
// Return the length of the structure in bytes,
// byte alligned.
uint32 read_swf_rect(linput_t *li, SWFRECT *rect);

// Read and fill A SWFMATRIX structure from the
// current read pointer.
// Return the length of the structure in bytes,
// byte alligned
uint32 read_swf_matrix(linput_t *li, SWFMATRIX *matrix);

// Read and fill A SWFCXFORMWITHALPHA structure
// from the current read pointer.
// Return the length of the structure in bytes,
// byte alligned
uint32 read_swf_cxformwithalpha(linput_t *li, SWFCXFORMWITHALPHA *cx);

// Read an s24 (3 byte) value.
// Return its size(allways 3).
uint8 read_s24(linput_t *li, uint32 &value);

// Read an u30 variable encoding value.
// Return its size byte alligned.
uint8 read_u30(linput_t *li, uint32 &value);

// Read an u32 variable encoding value.
// Return its size byte alligned.
uint8 read_u32(linput_t *li, uint32 &value);

// Read an s32 variable encoding value.
// Return its size byte alligned.
uint8 read_s32(linput_t *li, int32 &value);

#endif