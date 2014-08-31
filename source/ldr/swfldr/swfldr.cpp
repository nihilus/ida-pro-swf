/*
*  Interactive disassembler (IDA).
*  LOADER for Adobe Flash Files
*  Marian RADU <marianra@microsoft.com>
*/


#include "../idaldr.h"
#include "swfstructs.h"
#include "swfldr.h"

#define PLFM_SWF_AS3    0x8A53
#define PLFM_SWF_AS2    0x8A54

bool header_parser (linput_t *li, ea_t start, ea_t end, bool isSWC)
{
    //name header elements
    do_name_anyway(start, "Magic1"); doByte(start, 1); op_chr(start, 0);
    start ++;
    do_name_anyway(start, "Magic2"); doByte(start, 1); op_chr(start, 0);
    start ++;
    do_name_anyway(start, "Magic3"); doByte(start, 1); op_chr(start, 0);
    start ++;
    do_name_anyway(start, "Version"); doByte(start, 1); op_num(start, 0);
    start ++;

    if ( isSWC )
    {
        do_name_anyway(start, "DecryptedFileLength"); doDwrd(start, 4); op_num(start, 0);
        start += 4;
    }
    else
    {
        do_name_anyway(start, "FileLength"); doDwrd(start, 4); op_num(start, 0);
        start += 4;
        uint32 rect_size = end - (start + 4);
        do_name_anyway(start, "FrameSize"); doByte(start, rect_size); op_num(start, 0);
        start += rect_size;
        do_name_anyway(start, "FrameRate"); doWord(start, 2); op_num(start, 0);
        start += 2;
        do_name_anyway(start, "FrameCount"); doWord(start, 2); op_num(start, 0);
        start += 2;
    }

    return true;
}

bool unk_tag_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr) 
{
    char description[MAXSTR];
    uint16 tagCodeAndLength;

    qlseek(li, start, SEEK_SET);
    lread2bytes(li, &tagCodeAndLength, 0);
    uint16 tagCode = tagCodeAndLength >> 6;

    qsnprintf(description, MAXSTR, "%s.TagCodeAndLength", tags[tagCode].tagName);
    set_cmt(start, description, false); doWord(start, 2); op_num(start, 0); 
    start += 2;

    if ( hasLongHdr )
    {
        qsnprintf(description, MAXSTR, "%s.Length", tags[tagCode].tagName);
        set_cmt(start, description, false); doDwrd(start, 4); op_num(start, 0); 
    }

    return true; 
}

bool set_bgcolor_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr)
{
    ea_t orig_start = start;

    //skip RECORDHEADER field    
    hasLongHdr ? start += 6 : start += 2;

    set_cmt(start, "SetBackgroundColor.RGB.Red", false);doByte(start, 1); op_num(start, 0);
    start ++;
    set_cmt(start, "SetBackgroundColor.RGB.Green", false);doByte(start, 1); op_num(start, 0);
    start ++;
    set_cmt(start, "SetBackgroundColor.RGB.Blue", false);doByte(start, 1); op_num(start, 0);
    start ++;

    //call default tag parser
    return unk_tag_parser(li, orig_start, end, hasLongHdr);
}
bool do_action_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr)
{
    uint16 tagCodeAndLength = 0;
    char entry_name[MAXSTR];

    qlseek(li, start, SEEK_SET);
    lread2bytes(li, &tagCodeAndLength, 0);
    //skip long lenght field
    if ( hasLongHdr )
        qlseek(li, 4, SEEK_CUR);

    switch( tagCodeAndLength >> 6 )
    {
    case 59: /* DoInitAction */
        {
            int32 offset = qltell(li);            
            set_cmt(offset , "DoInitAction.SpriteID", false); doWord(offset, 2); op_num(offset, 0); 
            offset += 2;

            qsnprintf(entry_name, MAXSTR, "DoInitAction_%X", offset);
            add_entry(offset, offset, entry_name, true);
        }
        break;
    case 12: /* DoAction */
        {            
            int32 offset = qltell(li);
            qsnprintf(entry_name, MAXSTR, "DoAction_%X", offset);
            add_entry(offset, offset, entry_name, true);
        }
        break;
    }

    //call default tag parser
    return unk_tag_parser(li, start, end, hasLongHdr);
}

bool define_button_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr)
{
    ea_t orig_start = start;

    //skip RECORDHEADER field    
    hasLongHdr ? start += 6 : start += 2;

    set_cmt(start, "DefineButton.ButtonId", false); doWord(start, 2); op_num(start, 0);
    start += 2;

    uint8 endFlag = 0;
    uint8 buttonFlags = 0;

    do {
        //parse BUTTONRECORD array (one or more entries)

        qlseek(li, start, SEEK_SET);
        buttonFlags = qlgetc(li);
        set_cmt(start, "DefineButton.BUTTONRECORD.Flags", false); doByte(start, 1); op_num(start, 0);
        start ++;

        set_cmt(start, "DefineButton.BUTTONRECORD.CharacterId", false); doWord(start, 2); op_num(start, 0);
        start += 2;

        set_cmt(start, "DefineButton.BUTTONRECORD.PlaceDepth", false); doWord(start, 2); op_num(start, 0);
        start += 2;

        qlseek(li, start, SEEK_SET);
        uint32 matrix_size = read_swf_matrix(li, NULL); 
        set_cmt(start, "DefineButton.BUTTONRECORD.PlaceMatrix", false); doByte(start, matrix_size); op_num(start, 0);
        start += matrix_size;

        endFlag = qlgetc(li);

    } while (endFlag != 0);

    set_cmt(start, "DefineButton.CharacterEndFlag", false); doByte(start, 1); op_num(start, 0);
    start ++;

    //make code at start of button actions 
    char entry_name[MAXSTR];
    qsnprintf(entry_name, MAXSTR, "OnClickAndRelease_%X", start);
    add_entry(start, start, NULL, true);

    //call default tag parser
    return unk_tag_parser(li, orig_start, end, hasLongHdr);
}

bool define_button2_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr)
{
    ea_t orig_start = start;

    //skip RECORDHEADER field    
    hasLongHdr ? start += 6 : start += 2;

    set_cmt(start, "DefineButton2.ButtonId", false); doWord(start, 2); op_num(start, 0);
    start += 2;

    set_cmt(start, "DefineButton2.Flags", false); doByte(start, 1); op_num(start, 0);
    start ++;

    uint16 action_offset = 0;
    qlseek(li, start, SEEK_SET);
    lread2bytes(li, &action_offset, 0);
    set_cmt(start, "DefineButton2.ActionOffset", false); doWord(start, 2); op_num(start, 0);
    
    if (action_offset) 
    {
        //set as code segment
        set_segm_class( getseg(start), CLASS_CODE );

        uint16 condActionSize = 0;
        ea_t offset = start + action_offset;        

        do{
            offset += condActionSize;

            qlseek(li, offset, SEEK_SET);
            lread2bytes(li, &condActionSize, 0); 

            set_cmt(offset, "DefineButton2.BUTTONCONDACTION.CondActionSize", false); doWord(offset, 2); op_num(offset, 0);
            offset += 2;

            uint16 buttonevent = 0;
            lread2bytes(li, &buttonevent, 1); //read big endian
            set_cmt(offset, "DefineButton2.BUTTONCONDACTION.Flags", false); doWord(offset, 2); op_num(offset, 0);
            offset += 2;

            char entry_name[MAXSTR];
            char eventName[MAX_SWF_EVENT_NAME];
            buttonevent2string(buttonevent, eventName, MAX_SWF_EVENT_NAME);
            qsnprintf(entry_name, MAXSTR, "%s_%X", eventName, offset);
            add_entry(offset, offset, entry_name, true);

            //done so the first instr in do will work properly
            offset -= 4;
        } while( condActionSize );        
    }

    start += 2;

    uint8 flags = 0;
    qlseek(li, start, SEEK_SET);
    flags = qlgetc(li);

    do {
        //parse BUTTONRECORD array (one or more entries)       
        set_cmt(start, "DefineButton2.BUTTONRECORD.Flags", false); doByte(start, 1); op_num(start, 0);
        start ++;

        set_cmt(start, "DefineButton2.BUTTONRECORD.CharacterId", false); doWord(start, 2); op_num(start, 0);
        start += 2;

        set_cmt(start, "DefineButton2.BUTTONRECORD.PlaceDepth", false); doWord(start, 2); op_num(start, 0);
        start += 2;

        qlseek(li, start, SEEK_SET);
        uint32 structSize = read_swf_matrix(li, NULL); 
        set_cmt(start, "DefineButton2.BUTTONRECORD.PlaceMatrix", false); doByte(start, structSize); op_num(start, 0);
        start += structSize;

        structSize = read_swf_cxformwithalpha(li, NULL);
        set_cmt(start, "DefineButton2.BUTTONRECORD.ColorTransform", false); doByte(start, structSize); op_num(start, 0);
        start += structSize;

        if ( flags & 0x10 /* ButtonHasFilterList */ )
        {
            qlseek(li, start, SEEK_SET);
            uint8 nbFilters = qlgetc(li);
            set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.NumberOfFilters", false); doByte(start, 1); op_num(start, 0);
            start ++;

            //parse FILTER struct
            uint8 filterID;
            for (uint8 i =0; i < nbFilters; i++)
            {
                qlseek(li, start, SEEK_SET);
                filterID = qlgetc(li);
                set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.FilterId", false); doByte(start, 1); op_num(start, 0);
                start ++;

                switch (filterID)
                {
                case DROPSHADOWFILTER:
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.DROPSHADOWFILTER.DropShadowColor.Red", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.DROPSHADOWFILTER.DropShadowColor.Green", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.DROPSHADOWFILTER.DropShadowColor.Blue", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.DROPSHADOWFILTER.DropShadowColor.Alpha", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.DROPSHADOWFILTER.BlurX", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.DROPSHADOWFILTER.BlurY", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.DROPSHADOWFILTER.Angle", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.DROPSHADOWFILTER.Distance", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.DROPSHADOWFILTER.Strength", false);doWord(start, 2); op_num(start, 0);
                    start += 2;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.DROPSHADOWFILTER.Flags", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    break;
                case BLURFILTER:
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BLURFILTER.BlurX", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BLURFILTER.BlurY", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BLURFILTER.Passes", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    break;
                case GLOWFILTER:
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GLOWFILTER.GlowColor.Red", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GLOWFILTER.GlowColor.Green", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GLOWFILTER.GlowColor.Blue", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GLOWFILTER.GlowColor.Alpha", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GLOWFILTER.BlurX", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GLOWFILTER.BlurY", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GLOWFILTER.Strength", false);doWord(start, 2); op_num(start, 0);
                    start += 2;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GLOWFILTER.Flags", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    break;
                case BEVELFILTER:
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BEVELFILTER.ShadowColor.Red", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BEVELFILTER.ShadowColor.Green", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BEVELFILTER.ShadowColor.Blue", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BEVELFILTER.ShadowColor.Alpha", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BEVELFILTER.HighlightColor.Red", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BEVELFILTER.HighlightColor.Green", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BEVELFILTER.HighlightColor.Blue", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BEVELFILTER.HighlightColor.Alpha", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BEVELFILTER.BlurX", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BEVELFILTER.BlurY", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BEVELFILTER.Angle", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BEVELFILTER.Distance", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BEVELFILTER.Strength", false);doWord(start, 2); op_num(start, 0);
                    start += 2;
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.BEVELFILTER.Flags", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    break;
                case GRADIENTGLOWFILTER:
                    {
                        uint8 numColors = qlgetc(li);
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTGLOWFILTER.NumColors", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                        for (uint8 i = 0; i < numColors; i++)
                        {
                            set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTGLOWFILTER.GradientColors.Red", false);doByte(start, 1); op_num(start, 0);
                            start ++;
                            set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTGLOWFILTER.GradientColors.Green", false);doByte(start, 1); op_num(start, 0);
                            start ++;
                            set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTGLOWFILTER.GradientColors.Blue", false);doByte(start, 1); op_num(start, 0);
                            start ++;
                            set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTGLOWFILTER.GradientColors.Alpha", false);doByte(start, 1); op_num(start, 0);
                            start ++;
                        }
                        for (uint8 i = 0; i < numColors; i++)
                        {
                            set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTGLOWFILTER.GradientRatio", false);doByte(start, 1); op_num(start, 0);
                            start ++;
                        }
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTGLOWFILTER.BlurX", false);doDwrd(start, 4); op_num(start, 0);
                        start += 4;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTGLOWFILTER.BlurY", false);doDwrd(start, 4); op_num(start, 0);
                        start += 4;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTGLOWFILTER.Angle", false);doDwrd(start, 4); op_num(start, 0);
                        start += 4;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTGLOWFILTER.Distance", false);doDwrd(start, 4); op_num(start, 0);
                        start += 4;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTGLOWFILTER.Strength", false);doWord(start, 2); op_num(start, 0);
                        start += 2;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTGLOWFILTER.Flags", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                    }
                    break;
                case CONVOLUTIONFILTER:
                    {
                        uint8 matrixX = qlgetc(li),
                            matrixY = qlgetc(li);
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.CONVOLUTIONFILTER.MatrixX", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.CONVOLUTIONFILTER.MatrixY", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.CONVOLUTIONFILTER.Divisor", false);doDwrd(start, 4); op_num(start, 0);
                        start += 4;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.CONVOLUTIONFILTER.Bias", false);doDwrd(start, 4); op_num(start, 0);
                        start += 4;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.CONVOLUTIONFILTER.Matrix", false);doDwrd(start, matrixX*matrixY*4); op_num(start, 0);
                        start += matrixX*matrixY*4;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.CONVOLUTIONFILTER.DefaultColor.Red", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.CONVOLUTIONFILTER.DefaultColor.Green", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.CONVOLUTIONFILTER.DefaultColor.Blue", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.CONVOLUTIONFILTER.DefaultColor.Alpha", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.CONVOLUTIONFILTER.Flags", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                    }
                    break;
                case COLORMATRIXFILTER:
                    set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.COLORMATRIXFILTER", false);doDwrd(start, 20); op_num(start, 0);
                    start += 4*20;
                    break;
                case GRADIENTBEVELFILTER:
                    {
                        uint8 numColors = qlgetc(li);
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTBEVELFILTER.NumColors", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                        for (uint8 i = 0; i < numColors; i++)
                        {
                            set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTBEVELFILTER.GradientColors.Red", false);doByte(start, 1); op_num(start, 0);
                            start ++;
                            set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTBEVELFILTER.GradientColors.Green", false);doByte(start, 1); op_num(start, 0);
                            start ++;
                            set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTBEVELFILTER.GradientColors.Blue", false);doByte(start, 1); op_num(start, 0);
                            start ++;
                            set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTBEVELFILTER.GradientColors.Alpha", false);doByte(start, 1); op_num(start, 0);
                            start ++;
                        }
                        for (uint8 i = 0; i < numColors; i++)
                        {
                            set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTBEVELFILTER.GradientRatio", false);doByte(start, 1); op_num(start, 0);
                            start ++;
                        }
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTBEVELFILTER.BlurX", false);doDwrd(start, 4); op_num(start, 0);
                        start += 4;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTBEVELFILTER.BlurY", false);doDwrd(start, 4); op_num(start, 0);
                        start += 4;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTBEVELFILTER.Angle", false);doDwrd(start, 4); op_num(start, 0);
                        start += 4;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTBEVELFILTER.Distance", false);doDwrd(start, 4); op_num(start, 0);
                        start += 4;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTBEVELFILTER.Strength", false);doWord(start, 2); op_num(start, 0);
                        start += 2;
                        set_cmt(start, "DefineButton2.BUTTONRECORD.FILTERLIST.FILTER.GRADIENTBEVELFILTER.Flags", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                    }
                    break;
                }//switch
            }//for
        }

        if ( flags & 0x20 /* ButtonHasBlendMode */ ) 
        {
            set_cmt(start, "DefineButton2.BUTTONRECORD.BlendMode", false);doByte(start, 1); op_num(start, 0);
            start ++;
        }

        qlseek(li, start, SEEK_SET);
        flags = qlgetc(li);

    } while (flags != 0);
    
    set_cmt(start, "DefineButton2.CharacterEndFlag", false); doByte(start, 1); op_num(start, 0);

    //call default tag parser
    return unk_tag_parser(li, orig_start, end, hasLongHdr);
}

bool place_obj2_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr)
{
    ea_t orig_start = start;
    uint8 placeFlags = 0;

    //skip RECORDHEADER field    
    hasLongHdr ? start += 6 : start += 2;

    qlseek(li, start, SEEK_SET);
    placeFlags = qlgetc(li);
    set_cmt(start, "PlaceObject2.PlaceFlags", false); doByte(start, 1); op_num(start, 0);
    start ++;

    set_cmt(start, "PlaceObject2.Depth", false); doWord(start, 2); op_num(start, 0);
    start += 2;

    if ( placeFlags & 0x02 /* PlaceFlagHasCharacter */)
    {
        set_cmt(start, "PlaceObject2.CharacterId", false); doWord(start, 2); op_num(start, 0);
        start += 2;
    }

    if ( placeFlags & 0x04 /* PlaceFlagHasMatrix */)
    {
        qlseek(li, start, SEEK_SET);
        uint32 structSize = read_swf_matrix(li, NULL); 
        set_cmt(start, "PlaceObject2.Matrix", false); doByte(start, structSize); op_num(start, 0);
        start += structSize;
    }

    if ( placeFlags & 0x08 /* PlaceFlagHasColorTransform */)
    {
        qlseek(li, start, SEEK_SET);
        uint32 structSize = read_swf_cxformwithalpha(li, NULL); 
        set_cmt(start, "PlaceObject2.ColorTransform", false); doByte(start, structSize); op_num(start, 0);
        start += structSize;
    }

    if ( placeFlags & 0x10 /* PlaceFlagHasRatio */)
    {
        set_cmt(start, "PlaceObject2.Ratio", false); doWord(start, 2); op_num(start, 0);
        start += 2;
    }

    if ( placeFlags & 0x20 /* PlaceFlagHasName */)
    { 
        size_t name_len = get_max_ascii_length(start, ASCSTR_C);
        set_cmt(start, "PlaceObject2.Name", false); doASCI(start, name_len);
        start += name_len;
    }

    if ( placeFlags & 0x40 /* PlaceFlagHasClipDepth */)
    {
        set_cmt(start, "PlaceObject2.ClipDepth", false); doWord(start, 2); op_num(start, 0);
        start += 2;
    }

    if ( placeFlags & 0x80 /* PlaceFlagHasClipActions */)
    {    
        //set as code segment
        set_segm_class( getseg(start), CLASS_CODE );

        set_cmt(start, "PlaceObject2.CLIPACTIONS.Reserved", false); doWord(start, 2); op_num(start, 0);
        start += 2;

        //assuming we have mapped the header
        qlseek(li, 3, SEEK_SET);
        uint8 swf_version = qlgetc(li);
        if (swf_version >= 6)
        {
            set_cmt(start, "PlaceObject2.CLIPACTIONS.AllEventFlags", false); doDwrd(start, 4); op_num(start, 0);
            start += 4;
        } 
        else
        {
            set_cmt(start, "PlaceObject2.CLIPACTIONS.AllEventFlags", false); doWord(start, 2); op_num(start, 0);
            start += 2;
        }

        //start of CLIPACTIONRECORD
        uint32 eventFlags = 0;
        uint16 eventFlags16 = 0;
        qlseek(li, start, SEEK_SET);
        if (swf_version >= 6)
        {
            //read big endian
            lread4bytes(li, &eventFlags, 1);
        } 
        else
        {
            //read big endian
            lread2bytes(li, &eventFlags16, 1);
            eventFlags |= ((uint32)eventFlags16)<<16;
        }

        do
        {
            if (swf_version >= 6)
            {
                set_cmt(start, "PlaceObject2.CLIPACTIONRECORD.EventFlag", false); doDwrd(start, 4); op_num(start, 0);
                start += 4;
            } 
            else
            {
                set_cmt(start, "PlaceObject2.CLIPACTIONRECORD.EventFlag", false); doWord(start, 2); op_num(start, 0);
                start += 2;
            }

            uint32 next_record = 0;
            //qlseek(li, start, SEEK_SET);
            lread4bytes(li, &next_record, 0);
            set_cmt(start, "PlaceObject2.CLIPACTIONRECORD.ActionRecordSize", false); doDwrd(start, 4); op_num(start, 0);
            start += 4;
            next_record += start;

            if ( (swf_version >= 6) && (eventFlags & 0x0200 /* ClipEventKeyPress */) )
            {
                set_cmt(start, "PlaceObject2.CLIPACTIONRECORD.KeyCode", false); doByte(start, 1); op_num(start, 0);
                start ++;
            }

            //ACTIONRECORD
            char entry_name[MAXSTR];
            char eventName[MAX_SWF_EVENT_NAME];
            
            event2string(eventFlags, eventName, MAX_SWF_EVENT_NAME);
            qsnprintf(entry_name, MAXSTR, "%s_%X", eventName, start);
            add_entry(start, start, entry_name, true);

            //goto next record
            qlseek(li, next_record, SEEK_SET);
            start = next_record;
            if (swf_version >= 6)
            {
                //read big endian
                lread4bytes(li, &eventFlags, 1);
            } 
            else
            {
                //read big endian
                lread2bytes(li, &eventFlags16, 1);
                eventFlags |= ((uint32)eventFlags16)<<16;
            }
        }
        while( eventFlags );

        if (swf_version >= 6)
        {
            set_cmt(start, "PlaceObject2.CLIPACTION.EndFlag", false); doDwrd(start, 4); op_num(start, 0);
            start += 4;
        } 
        else
        {
            set_cmt(start, "PlaceObject2.CLIPACTION.EndFlag", false); doWord(start, 2); op_num(start, 0);
            start += 2;
        }
    }//if

    //call default tag parser
    return unk_tag_parser(li, orig_start, end, hasLongHdr);
}

bool place_obj3_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr)
{
    ea_t orig_start = start;
    uint8 placeFlags1 = 0,
        placeFlags2 = 0;

    //skip RECORDHEADER field    
    hasLongHdr ? start += 6 : start += 2;

    qlseek(li, start, SEEK_SET);
    placeFlags1 = qlgetc(li);
    set_cmt(start, "PlaceObject3.PlaceFlags1", false); doByte(start, 1); op_num(start, 0);
    start ++;

    placeFlags2 = qlgetc(li);
    set_cmt(start, "PlaceObject3.PlaceFlags2", false); doByte(start, 1); op_num(start, 0);
    start ++;

    set_cmt(start, "PlaceObject3.Depth", false); doWord(start, 2); op_num(start, 0);
    start += 2;

    if ( (placeFlags2 & 0x08 /* PlaceFlagHasClassName */) ||
        ((placeFlags2 & 0x10 /* PlaceFlagHasImage */) && (placeFlags1 & 0x02 /* PlaceFlagHasCharacter */))
         )
    {
        size_t name_len = get_max_ascii_length(start, ASCSTR_C);
        set_cmt(start, "PlaceObject3.ClassName", false); doASCI(start, name_len);
        start += name_len;
    }

    if (placeFlags1 & 0x02 /* PlaceFlagHasCharacter */)
    {
        set_cmt(start, "PlaceObject3.CharacterId", false); doWord(start, 2); op_num(start, 0);
        start += 2;
    }

    if ( placeFlags1 & 0x04 /* PlaceFlagHasMatrix */)
    {
        qlseek(li, start, SEEK_SET);
        uint32 structSize = read_swf_matrix(li, NULL); 
        set_cmt(start, "PlaceObject3.Matrix", false); doByte(start, structSize); op_num(start, 0);
        start += structSize;
    }

    if ( placeFlags1 & 0x08 /* PlaceFlagHasColorTransform */)
    {
        qlseek(li, start, SEEK_SET);
        uint32 structSize = read_swf_cxformwithalpha(li, NULL); 
        set_cmt(start, "PlaceObject3.ColorTransform", false); doByte(start, structSize); op_num(start, 0);
        start += structSize;
    }

    if ( placeFlags1 & 0x10 /* PlaceFlagHasRatio */)
    {
        set_cmt(start, "PlaceObject3.Ratio", false); doWord(start, 2); op_num(start, 0);
        start += 2;
    }

    if ( placeFlags1 & 0x20 /* PlaceFlagHasName */)
    { 
        size_t name_len = get_max_ascii_length(start, ASCSTR_C);
        set_cmt(start, "PlaceObject3.Name", false); doASCI(start, name_len);
        start += name_len;
    }

    if ( placeFlags1 & 0x40 /* PlaceFlagHasClipDepth */)
    {
        set_cmt(start, "PlaceObject3.ClipDepth", false); doWord(start, 2); op_num(start, 0);
        start += 2;
    }

    if ( placeFlags2 & 0x01 /* PlaceFlagHasFilterList */ )
    {
        qlseek(li, start, SEEK_SET);
        uint8 nbFilters = qlgetc(li);
        set_cmt(start, "PlaceObject3.FILTERLIST.NumberOfFilters", false); doByte(start, 1); op_num(start, 0);
        start ++;

        //parse FILTER struct
        uint8 filterID;
        for (uint8 i =0; i < nbFilters; i++)
        {
            qlseek(li, start, SEEK_SET);
            filterID = qlgetc(li);
            set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.FilterId", false); doByte(start, 1); op_num(start, 0);
            start ++;

            switch (filterID)
            {
            case DROPSHADOWFILTER:
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.DROPSHADOWFILTER.DropShadowColor.Red", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.DROPSHADOWFILTER.DropShadowColor.Green", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.DROPSHADOWFILTER.DropShadowColor.Blue", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.DROPSHADOWFILTER.DropShadowColor.Alpha", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.DROPSHADOWFILTER.BlurX", false);doDwrd(start, 4); op_num(start, 0);
                start += 4;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.DROPSHADOWFILTER.BlurY", false);doDwrd(start, 4); op_num(start, 0);
                start += 4;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.DROPSHADOWFILTER.Angle", false);doDwrd(start, 4); op_num(start, 0);
                start += 4;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.DROPSHADOWFILTER.Distance", false);doDwrd(start, 4); op_num(start, 0);
                start += 4;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.DROPSHADOWFILTER.Strength", false);doWord(start, 2); op_num(start, 0);
                start += 2;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.DROPSHADOWFILTER.Flags", false);doByte(start, 1); op_num(start, 0);
                start ++;
                break;
            case BLURFILTER:
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BLURFILTER.BlurX", false);doDwrd(start, 4); op_num(start, 0);
                start += 4;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BLURFILTER.BlurY", false);doDwrd(start, 4); op_num(start, 0);
                start += 4;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BLURFILTER.Passes", false);doByte(start, 1); op_num(start, 0);
                start ++;
                break;
            case GLOWFILTER:
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GLOWFILTER.GlowColor.Red", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GLOWFILTER.GlowColor.Green", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GLOWFILTER.GlowColor.Blue", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GLOWFILTER.GlowColor.Alpha", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GLOWFILTER.BlurX", false);doDwrd(start, 4); op_num(start, 0);
                start += 4;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GLOWFILTER.BlurY", false);doDwrd(start, 4); op_num(start, 0);
                start += 4;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GLOWFILTER.Strength", false);doWord(start, 2); op_num(start, 0);
                start += 2;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GLOWFILTER.Flags", false);doByte(start, 1); op_num(start, 0);
                start ++;
                break;
            case BEVELFILTER:
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BEVELFILTER.ShadowColor.Red", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BEVELFILTER.ShadowColor.Green", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BEVELFILTER.ShadowColor.Blue", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BEVELFILTER.ShadowColor.Alpha", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BEVELFILTER.HighlightColor.Red", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BEVELFILTER.HighlightColor.Green", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BEVELFILTER.HighlightColor.Blue", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BEVELFILTER.HighlightColor.Alpha", false);doByte(start, 1); op_num(start, 0);
                start ++;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BEVELFILTER.BlurX", false);doDwrd(start, 4); op_num(start, 0);
                start += 4;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BEVELFILTER.BlurY", false);doDwrd(start, 4); op_num(start, 0);
                start += 4;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BEVELFILTER.Angle", false);doDwrd(start, 4); op_num(start, 0);
                start += 4;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BEVELFILTER.Distance", false);doDwrd(start, 4); op_num(start, 0);
                start += 4;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BEVELFILTER.Strength", false);doWord(start, 2); op_num(start, 0);
                start += 2;
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.BEVELFILTER.Flags", false);doByte(start, 1); op_num(start, 0);
                start ++;
                break;
            case GRADIENTGLOWFILTER:
                {
                    uint8 numColors = qlgetc(li);
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTGLOWFILTER.NumColors", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    for (uint8 i = 0; i < numColors; i++)
                    {
                        set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTGLOWFILTER.GradientColors.Red", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                        set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTGLOWFILTER.GradientColors.Green", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                        set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTGLOWFILTER.GradientColors.Blue", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                        set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTGLOWFILTER.GradientColors.Alpha", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                    }
                    for (uint8 i = 0; i < numColors; i++)
                    {
                        set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTGLOWFILTER.GradientRatio", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                    }
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTGLOWFILTER.BlurX", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTGLOWFILTER.BlurY", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTGLOWFILTER.Angle", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTGLOWFILTER.Distance", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTGLOWFILTER.Strength", false);doWord(start, 2); op_num(start, 0);
                    start += 2;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTGLOWFILTER.Flags", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                }
                break;
            case CONVOLUTIONFILTER:
                {
                    uint8 matrixX = qlgetc(li),
                        matrixY = qlgetc(li);
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.CONVOLUTIONFILTER.MatrixX", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.CONVOLUTIONFILTER.MatrixY", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.CONVOLUTIONFILTER.Divisor", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.CONVOLUTIONFILTER.Bias", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.CONVOLUTIONFILTER.Matrix", false);doDwrd(start, matrixX*matrixY*4); op_num(start, 0);
                    start += matrixX*matrixY*4;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.CONVOLUTIONFILTER.DefaultColor.Red", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.CONVOLUTIONFILTER.DefaultColor.Green", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.CONVOLUTIONFILTER.DefaultColor.Blue", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.CONVOLUTIONFILTER.DefaultColor.Alpha", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.CONVOLUTIONFILTER.Flags", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                }
                break;
            case COLORMATRIXFILTER:
                set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.COLORMATRIXFILTER", false);doDwrd(start, 20); op_num(start, 0);
                start += 4*20;
                break;
            case GRADIENTBEVELFILTER:
                {
                    uint8 numColors = qlgetc(li);
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTBEVELFILTER.NumColors", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                    for (uint8 i = 0; i < numColors; i++)
                    {
                        set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTBEVELFILTER.GradientColors.Red", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                        set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTBEVELFILTER.GradientColors.Green", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                        set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTBEVELFILTER.GradientColors.Blue", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                        set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTBEVELFILTER.GradientColors.Alpha", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                    }
                    for (uint8 i = 0; i < numColors; i++)
                    {
                        set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTBEVELFILTER.GradientRatio", false);doByte(start, 1); op_num(start, 0);
                        start ++;
                    }
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTBEVELFILTER.BlurX", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTBEVELFILTER.BlurY", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTBEVELFILTER.Angle", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTBEVELFILTER.Distance", false);doDwrd(start, 4); op_num(start, 0);
                    start += 4;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTBEVELFILTER.Strength", false);doWord(start, 2); op_num(start, 0);
                    start += 2;
                    set_cmt(start, "PlaceObject3.FILTERLIST.FILTER.GRADIENTBEVELFILTER.Flags", false);doByte(start, 1); op_num(start, 0);
                    start ++;
                }
                break;
            }//switch
        }//for
    }

    if ( placeFlags2 & 0x02 /* PlaceFlagHasBlendMode */ ) 
    {
        set_cmt(start, "PlaceObject3.BlendMode", false);doByte(start, 1); op_num(start, 0);
        start ++;
    }

    if ( placeFlags2 & 0x04 /* PlaceFlagHasCacheAsBitmap */ ) 
    {
        set_cmt(start, "PlaceObject3.BitmapCache", false);doByte(start, 1); op_num(start, 0);
        start ++;
    }

    if ( placeFlags1 & 0x80 /* PlaceFlagHasClipActions */)
    {    
        //set as code segment
        set_segm_class( getseg(start), CLASS_CODE );

        set_cmt(start, "PlaceObject3.CLIPACTIONS.Reserved", false); doWord(start, 2); op_num(start, 0);
        start += 2;

        //assuming we have mapped the header
        qlseek(li, 3, SEEK_SET);
        uint8 swf_version = qlgetc(li);
        if (swf_version >= 6)
        {
            set_cmt(start, "PlaceObject3.CLIPACTIONS.AllEventFlags", false); doDwrd(start, 4); op_num(start, 0);
            start += 4;
        } 
        else
        {
            set_cmt(start, "PlaceObject3.CLIPACTIONS.AllEventFlags", false); doWord(start, 2); op_num(start, 0);
            start += 2;
        }

        //start of CLIPACTIONRECORD
        uint32 eventFlags = 0;
        uint16 eventFlags16 = 0;
        qlseek(li, start, SEEK_SET);
        if (swf_version >= 6)
        {
            //read big endian
            lread4bytes(li, &eventFlags, 1);
        } 
        else
        {
            //read big endian
            lread2bytes(li, &eventFlags16, 1);
            eventFlags |= ((uint32)eventFlags16)<<16;
        }

        do
        {
            if (swf_version >= 6)
            {
                set_cmt(start, "PlaceObject3.CLIPACTIONRECORD.EventFlag", false); doDwrd(start, 4); op_num(start, 0);
                start += 4;
            } 
            else
            {
                set_cmt(start, "PlaceObject3.CLIPACTIONRECORD.EventFlag", false); doWord(start, 2); op_num(start, 0);
                start += 2;
            }

            uint32 next_record = 0;
            //qlseek(li, start, SEEK_SET);
            lread4bytes(li, &next_record, 0);
            set_cmt(start, "PlaceObject3.CLIPACTIONRECORD.ActionRecordSize", false); doDwrd(start, 4); op_num(start, 0);
            start += 4;
            next_record += start;

            if ( (swf_version >= 6) && (eventFlags & 0x0200 /* ClipEventKeyPress */) )
            {
                set_cmt(start, "PlaceObject3.CLIPACTIONRECORD.KeyCode", false); doByte(start, 1); op_num(start, 0);
                start ++;
            }

            //ACTIONRECORD
            char entry_name[MAXSTR];
            char eventName[MAX_SWF_EVENT_NAME];
            
            event2string(eventFlags, eventName, MAX_SWF_EVENT_NAME);
            qsnprintf(entry_name, MAXSTR, "%s_%X", eventName, start);
            add_entry(start, start, entry_name, true);

            //goto next record
            qlseek(li, next_record, SEEK_SET);
            start = next_record;
            if (swf_version >= 6)
            {
                //read big endian
                lread4bytes(li, &eventFlags, 1);
            } 
            else
            {
                //read big endian
                lread2bytes(li, &eventFlags16, 1);
                eventFlags |= ((uint32)eventFlags16)<<16;
            }
        }
        while( eventFlags );

        if (swf_version >= 6)
        {
            set_cmt(start, "PlaceObject3.CLIPACTION.EndFlag", false); doDwrd(start, 4); op_num(start, 0);
            start += 4;
        } 
        else
        {
            set_cmt(start, "PlaceObject3.CLIPACTION.EndFlag", false); doWord(start, 2); op_num(start, 0);
            start += 2;
        }
    }//if

    //call default tag parser
    return unk_tag_parser(li, orig_start, end, hasLongHdr);
}
bool define_sprite_parser (linput_t *li, ea_t start_tag, ea_t end_tag, bool hasLongHdr_tag)
{
    ea_t start = start_tag;
    ea_t end;
    uint8 placeFlags = 0;

    //skip RECORDHEADER field    
    hasLongHdr_tag ? start += 6 : start += 2;

    set_cmt(start, "DefineSprite.SpriteId", false); doWord(start, 2); op_num(start, 0);
    start += 2;

    set_cmt(start, "DefineSprite.FrameCount", false); doWord(start, 2); op_num(start, 0);
    start += 2;

    qlseek(li, start, SEEK_SET);

    //start processing internal TAGs
    uint16  tagCodeAndLength = 0,
        tagCode = 0;
    uint8   tagLenghtShort = 0;
    uint32  tagLengthLong;
    bool    hasLongHdr;

    lread2bytes(li, &tagCodeAndLength, 0);

    end = start;
    while (tagCodeAndLength != 0 /* END TAG*/ && end < end_tag)
    {
        add_long_cmt(start, true, "=============== Sprite TAG ================================================");
        start = end;        

        tagCode = tagCodeAndLength >> 6;
        tagLenghtShort = tagCodeAndLength & 0x3F; 
        tagLengthLong = 0;

        if ( tagLenghtShort == 0x3F )
        {
            //long length field is following                
            lread4bytes(li, &tagLengthLong, 0);
            end = start + 6 + tagLengthLong;
            hasLongHdr = true;
        }
        else
        {
            end = start + 2 + tagLenghtShort;
            hasLongHdr = false;
        }

        if ( tagCode < SWF_NAME_TAGS_NUMBER )
        {
            //call tag parsing function
            if ( ! tags[tagCode].tag_parser(li, start, end, hasLongHdr))
                msg("!!! Sprite Tag parsing failed: %s[#%d]!!!\n", tags[tagCode].tagName, tagCode);
        }
        else
        {
            //unknow tags can only have the default tag parser
            unk_tag_parser(li, start, end, hasLongHdr);
        }  

        //go to end of tag
        qlseek(li, end, SEEK_SET);

        //read next tag info
        lread2bytes(li, &tagCodeAndLength, 0);
    }//while

    //overwrite previous settings and set as DATA
    set_segm_class( getseg(start_tag), CLASS_DATA );

    //call default tag parser
    return unk_tag_parser(li, start_tag, end_tag, hasLongHdr_tag);
}

bool do_abc_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr)
{
    //skip RECORDHEADER field
    int32 offset;
    hasLongHdr ? offset = qlseek(li, start + 6, SEEK_SET) : offset = qlseek(li, start + 2, SEEK_SET);

    do_name_anyway(offset, "Flags"); doDwrd(offset, 4); op_num(offset, 0);
    offset += 4;

    size_t name_len = get_max_ascii_length(offset, ASCSTR_C);
    do_name_anyway(offset, "Name"); doASCI(offset, name_len);
    offset += name_len;

    do_name_anyway(offset, "MinorVersion"); doWord(offset, 2); op_num(offset, 0);
    offset += 2;

    do_name_anyway(offset, "ABCData"); doByte(offset, end - offset); op_num(offset, 0);

    //call default tag parser
    return unk_tag_parser(li, start, end, hasLongHdr);
}

// Check input file format. If recognized,
// then return 1 and fill 'fileformatname'
// otherwise return 0
static int __stdcall accept_file(linput_t *li,
                                 char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
    if ( n != 0 ) return 0;

    bool compressed;

    switch ( qlgetc(li) )
    {
    case 'F':
        compressed = false;
        break;
    case 'C':
        compressed = true;
        break;
    default:
        return 0;
    }

    uint16 magic;
    lread2bytes(li, &magic, 0);

    if ( magic != 'SW' ) return 0;

    uint8 ver = qlgetc(li);

    //CWS file compression is permited in SWF 6 or later only
    //if ( ver < 6 && compressed) return 0;

    qsnprintf(
        fileformatname, 
        MAX_FILE_FORMAT_NAME,
        "Shockwave Flash File (v%d)", ver
        );

    return 1;
}

// Load file into the database.
static void __stdcall load_file(linput_t *li, ushort neflag,
                                const char * /*fileformatname*/)
{
    bool is_swc = false;
    if ( qlgetc(li) == 'C' )
    {
        is_swc = true;
        msg("!!!CWS file compression is not supported!!!\n");
    }
    
    // Select SWF10 as the default processor.
    // Until I completely parse the DoABC tag
    // there is no need for the ActionScript3
    // processor.
    if ( /*ph.id != PLFM_SWF_AS3 ||*/ ph.id != PLFM_SWF_AS2 )
        set_processor_type("SWF-AS2", SETPROC_ALL|SETPROC_FATAL);

    // load full file into database
    file2base(li, 0, 0, qlseek(li, 0, SEEK_END), FILEREG_PATCHABLE);

    if ( is_swc )
    {
        // create 2 segments: header, zlib data.
        // ToDo: future version should be able to
        // decompress the date into the database.

        set_selector(1, 0);
        if ( !add_segm(1, 0, 8, "Header", NAME_UNDEF) )
            loader_failure("Cannot create segment for SWF Header!");
        // enable 32bit addressing
        set_segm_addressing (getseg ( 0 ), 1 );

        header_parser(li, 0, 8, is_swc);

        set_selector(2, 0);
        if ( !add_segm(2, 8, qlseek(li, 0, SEEK_END), "ZlibData", CLASS_DATA))
            loader_failure("Cannot create segment for Zlib data!");
        // enable 32bit addressing
        set_segm_addressing ( getseg ( 8 ), 1 );
    }
    else
    {
        // I'll load the SWF file into IDA by creating
        // a separate segment for each TAG. This seems
        // the natural way of mapping such a file, and
        // will also give the users the ability to 
        // quickly locate the desired tag by using the 
        // segment locator.
        //
        // Tags that contain ActionScript code will be
        // marked as code segments and all others as 
        // data segments.(probably there's another way
        // of doing this better)
        //
        // I'll also add every island of code to the 
        // entrypoint list. This will help in the 
        // analysis of potentially malicious flash files.

        sel_t sel = 1;
        set_selector(sel, 0);
        ea_t start = 0,
            end = 0;

        qlseek(li, 8, SEEK_SET);
        uint32 rect_size = read_swf_rect(li, NULL);
        end = 12 + rect_size;

        if ( !add_segm(sel, start, end, "Header", NAME_UNDEF) )
            loader_failure("Cannot create segment for SWF Header!");
        //enable 32bit addressing
        set_segm_addressing ( getseg ( start ), 1 );  

        header_parser(li, start, end, is_swc);

        uint16  tagCodeAndLength = 0,
                tagCode = 0;
        uint8   tagLenghtShort = 0;
        uint32  tagLengthLong;
        bool    hasLongHdr;

        qlseek(li, end, SEEK_SET);
        lread2bytes(li, &tagCodeAndLength, 0);

        while (tagCodeAndLength != 0 /* END TAG*/)
        {
            sel++;
            start = end;

            tagCode = tagCodeAndLength >> 6;
            tagLenghtShort = tagCodeAndLength & 0x3F; 
            tagLengthLong = 0;

            if ( tagLenghtShort == 0x3F )
            {
                //long length field is following                
                lread4bytes(li, &tagLengthLong, 0);
                end = start + 6 + tagLengthLong;
                hasLongHdr = true;
            }
            else
            {
                end = start + 2 + tagLenghtShort;
                hasLongHdr = false;
            }

            set_selector(sel, 0);

            if ( tagCode < SWF_NAME_TAGS_NUMBER )
            {
                //If an ActionScript3 tag was found 
                //change default processor type.
                //if ( tags[tagCode].isAction && tags[tagCode].swfAS == AS3)
                //    set_processor_type("SWF-AS3", SETPROC_ALL|SETPROC_FATAL);
                    
                //Process Named tag
                if ( !add_segm (
                    sel, start, end,  
                    tags[tagCode].tagName, 
                    tags[tagCode].isAction?CLASS_CODE:CLASS_DATA) 
                    )
                    loader_failure("Cannot create tag from offset %X to %X", start, end);
                //enable 32bit addressing
                set_segm_addressing ( getseg ( start ), 1 );

                //call tag parsing function
                if ( ! tags[tagCode].tag_parser(li, start, end, hasLongHdr))
                    msg("!!! Tag parsing failed: %s[#%d]!!!\n", tags[tagCode].tagName, tagCode);
            }
            else
            {
                //Process unknown tag
                char tagName[MAX_SWF_TAG_NAME];

                qsnprintf(tagName, MAX_SWF_TAG_NAME, "Tag%d", tagCode);
                
                if ( !add_segm (sel, start, end, tagName, CLASS_DATA) )
                    loader_failure("Cannot create tag from %X to %X", start, end);
                //enable 32bit addressing
                set_segm_addressing ( getseg ( start ), 1 );

                //unknow tags can only have the default tag parser
                unk_tag_parser(li, start, end, hasLongHdr);
            }  

            //go to end of tag
            qlseek(li, end, SEEK_SET);

            //read next tag info
            lread2bytes(li, &tagCodeAndLength, 0);
        }//while
    }//else
    
    add_long_cmt(inf.minEA, true, "\
+-------------------------------------------------------------------------+\n\
|                     Shockwave Flash(SWF) File Loader                    |\n\
|                           Author: Marian RADU                           |\n\
|                         <marianra@microsoft.com>                        |\n\
+-------------------------------------------------------------------------+\n\
");

}

//LOADER DESCRIPTION BLOCK
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  0,                            // loader flags
  accept_file,
  load_file,
  //create output file from the database.
  NULL,
  //take care of a moved segment (fix up relocations, for example)
  NULL,
  NULL,
};
