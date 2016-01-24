/*
*  Interactive disassembler (IDA).
*  LOADER for Adobe Flash Files
*  Marian RADU <marianra@microsoft.com>
*/

#include "swfstructs.h"

void event2string(uint32 event, char *name, int len)
{
    uint32 flag = 0x80000000;
    if (event & flag) { qsnprintf(name, len, "OnKeyUp"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnKeyDown"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnMouseUp"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnMouseDown"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnMouseMove"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnUnload"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnEnterFrame"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnLoad"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnDragOver"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnRollOut"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnRollOver"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnReleaseOutside"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnRelease"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnPress"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnInitialize"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnDataReceived"); return; }
    flag >>= 6;
    if (event & flag) { qsnprintf(name, len, "OnConstruct"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnKeyPress"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnDragOut"); return; }    

    //event unknown
    qsnprintf(name, len, "Unknown"); 
}


void buttonevent2string(uint16 event, char *name, int len)
{
    uint16 flag = 0x80;

    if (event & flag) { qsnprintf(name, len, "OnTrackDragOver"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnReleaseOutside"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnDragOver"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnDragOut"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnRelease"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnPress"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnRollOut"); return; }
    flag >>= 1;
    if (event & flag) { qsnprintf(name, len, "OnRollOver"); return; }
    
    event >>= 8;
    if (event & 0xFE) { qsnprintf(name, len, "OnKeyPress"); return; }
    if (event & 0x01) { qsnprintf(name, len, "OnTrakDragOut"); return; }

    //event unkwnown
    qsnprintf(name, len, "Unknown"); 
}

uint32 read_bits(linput_t *li, uint8 bitOffset, uint8 lenght)
{
    if ( (lenght == 0) || (lenght > 32) || (bitOffset > 7) ) 
        return 0;

    uint8 mask[8]  = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};
    uint32 result  = 0;
    uint8 b;    

    do {
        b = qlgetc(li);

        for (uint i = bitOffset; i < 8 && lenght > 0; i++)
        {            
            result += ((b & mask[i])? 1 : 0) << (--lenght);
        }

        bitOffset = 0;

    } while ( lenght ); //we need another byte

    return result;    
}

uint32 read_swf_rect(linput_t *li, SWFRECT *rect)
{
    SWFRECT r;
    int32 position;

    if (rect == NULL)
        rect = &r;

    //save read position
    position = qltell(li);

    uchar nBits = ((uchar)qlgetc(li)) >> 3;
    uint32 rect_size_bits = nBits*4 + 5;
    uint32 rect_size_bytes = rect_size_bits / 8;
    if(rect_size_bits % 8) rect_size_bytes++;

    //TODO: fill rect here

    return rect_size_bytes;
}

uint32 read_swf_matrix(linput_t *li, SWFMATRIX *matrix)
{
    SWFMATRIX m;
    int32 position;

    if (matrix == NULL)
        matrix = &m;

    //save read position
    position = qltell(li);

    uint8 fByte  = qlgetc(li);
    uint8 offset = 1;

    if (fByte & 0x80 /* hasScale */)
    {
        uint8 nScaleBits = (fByte & 0x7F) >> 2;

        offset = 6;

        if ( offset ) qlseek(li, -1, SEEK_CUR);

        matrix->scaleX = read_bits(li, offset, nScaleBits);
        offset = (offset + nScaleBits) % 8;
        //rewind input if needed
        if ( offset ) qlseek(li, -1, SEEK_CUR);

        matrix->scaleY = read_bits(li, offset, nScaleBits);
        offset = (offset + nScaleBits) % 8;  
        //don't rewind, keep alignment
        //if ( offset ) qlseek(li, -1, SEEK_CUR);
    }

    if ( offset ) qlseek(li, -1, SEEK_CUR);

    uint8 hasRotate = (uint8)read_bits(li, offset, 1);
    offset = (offset + 1) % 8;
    
    if ( hasRotate )
    {
        if ( offset ) qlseek(li, -1, SEEK_CUR);

        uint8 nRotateBits = (uint8)read_bits(li, offset, 5);
        offset = (offset + 5) % 8;
        if ( offset ) qlseek(li, -1, SEEK_CUR);

        matrix->rotateSkew0 = read_bits(li, offset, nRotateBits);
        offset = (offset + nRotateBits) % 8;        
        if ( offset ) qlseek(li, -1, SEEK_CUR);

        matrix->rotateSkew1 = read_bits(li, offset, nRotateBits);
        offset = (offset + nRotateBits) % 8;        
        //if ( offset ) qlseek(li, -1, SEEK_CUR);
    }

    if ( offset ) qlseek(li, -1, SEEK_CUR);

    uint8 nTranslateBits = (uint8)read_bits(li, offset, 5);
    offset = (offset + 5) % 8;    

    if (nTranslateBits)
    {
        if ( offset ) qlseek(li, -1, SEEK_CUR);

        matrix->translateX = read_bits(li, offset, nTranslateBits);
        offset = (offset + nTranslateBits) % 8;        
        if ( offset ) qlseek(li, -1, SEEK_CUR);

        matrix->translateY = read_bits(li, offset, nTranslateBits);

        //don't rewing as MATRIX is alligned to byte 
    }

    //return length of structure
    return qltell(li) - position;
}

uint32 read_swf_cxformwithalpha(linput_t *li, SWFCXFORMWITHALPHA *cx)
{
    SWFCXFORMWITHALPHA cxform;
    int32 position;
    uint8 offset;

    if (cx == NULL)
        cx = &cxform;

    position = qltell(li);

    uint8 flags = (uint8)qlgetc(li);

    qlseek(li, -1, SEEK_CUR);
    offset = 2;
    uint8 nBits = (uint8)read_bits(li, offset, 4);
    offset += 4;

    if (flags & 0x40/*HasMultItems*/)
    {
        if ( offset ) qlseek(li, -1, SEEK_CUR);

        cx->redMultTerm = read_bits(li, offset, nBits);
        offset = (offset + nBits) % 8;        
        if ( offset ) qlseek(li, -1, SEEK_CUR);

        cx->greenMultTerm = read_bits(li, offset, nBits);
        offset = (offset + nBits) % 8;        
        if ( offset ) qlseek(li, -1, SEEK_CUR);

        cx->blueMultTerm = read_bits(li, offset, nBits);
        offset = (offset + nBits) % 8;        
        if ( offset ) qlseek(li, -1, SEEK_CUR);

        cx->alphaMultTerm = read_bits(li, offset, nBits);
        offset = (offset + nBits) % 8;        
        //don't rewind to preserv byte allignment
        //if ( offset ) qlseek(li, -1, SEEK_CUR);
    }

    if (flags & 0x80/*HasAddItems*/)
    {
        if ( offset ) qlseek(li, -1, SEEK_CUR);

        cx->redAddTerm = read_bits(li, offset, nBits);
        offset = (offset + nBits) % 8;        
        if ( offset ) qlseek(li, -1, SEEK_CUR); 

        cx->greenAddTerm = read_bits(li, offset, nBits);
        offset = (offset + nBits) % 8;        
        if ( offset ) qlseek(li, -1, SEEK_CUR);

        cx->blueAddTerm = read_bits(li, offset, nBits);
        offset = (offset + nBits) % 8;        
        if ( offset ) qlseek(li, -1, SEEK_CUR);

        cx->alphaAddTerm = read_bits(li, offset, nBits);
        offset = (offset + nBits) % 8;  
        //don't rewind to preserv byte allignment
        //if ( offset ) qlseek(li, -1, SEEK_CUR);
    }

    //return length of structure
    return qltell(li) - position; 
}

uint8 read_s24(linput_t *li, uint32 &value)
{
    uint8 b1 = qlgetc(li),
        b2 = qlgetc(li),
        b3 = qlgetc(li);
    int32 v = 0;

    if(b3 & 0x80) {
        v = -1-((b3<<16|b2<<8|b1)^0xffffff);
    } else {
        v = b3<<16|b2<<8|b1;
    }

    value = v;

    return 3;
}

uint8 read_u30(linput_t *li, uint32 &value)
{
    uint8 readMore = 0,
        size = 0,
        byte = 0;
    uint32 v = 0;

    do
    {
        byte = qlgetc(li);
        size ++;

        if (byte &  0x80) //is high bit set?
        {
            readMore = 1;            
        }
        else
        {
            readMore = 0;
        }

        byte &= 0x7f; //wipe out high bit
        v += ((uint32)byte)<<((size - 1) * 7);
    }
    while (readMore && size < 5);

    //wipe out bits above 30
    value = v & 0x3FFFFFFF;

    return size;
}

uint8 read_u32(linput_t *li, uint32 &value)
{
    uint8 readMore = 0,
        size = 0,
        byte = 0;
    uint32 v = 0;

    do
    {
        byte = qlgetc(li);
        size ++;

        if (byte &  0x80) //is high bit set?
        {
            readMore = 1;            
        }
        else
        {
            readMore = 0;
        }

        byte &= 0x7f; //wipe out high bit
        v += ((uint32)byte)<<((size - 1) * 7);
    }
    while (readMore && size < 5);

    value = v;

    return size;
}

uint8 read_s32(linput_t *li, int32 &value)
{
    uint8 readMore = 0,
        size = 0,
        byte = 0;
    uint32 v = 0;

    do
    {
        byte = qlgetc(li);
        size ++;

        if (byte &  0x80) //is high bit set?
        {
            readMore = 1;            
        }
        else
        {
            readMore = 0;
            //set sign bit if the seventh bit of the last byte is set
            if (byte & 0x40){
                v &= 0x80;
                byte &= 0x3F; //wipe out sign bit
            }
        }

        byte &= 0x7f; //wipe out high bit
        v += ((uint32)byte)<<((size - 1) * 7);
    }
    while (readMore && size < 5);

    value = (int32)v;

    return size;
}