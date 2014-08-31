/*
*  Interactive disassembler (IDA).
*  LOADER for Adobe Flash Files
*  Marian RADU <marianra@microsoft.com>
*/

#include "swfstructs.h"

#ifndef __SWFLDR_H
#define __SWFLDR_H

typedef enum _SWFACTIONSCRIPT {
    AS2 = 1,
    AS3 = 2,
} SWFACTIONSCRIPT;

#define MAX_SWF_TAG_NAME      40
#define MAX_SWF_EVENT_NAME    50

typedef struct _SWFTAG {
    //Holds the name for known tags
    //and a default name for unknowns.
    char            tagName[MAX_SWF_TAG_NAME];

    //True if an ACTIONRECORD can reside inside the tag
    bool            isAction;

    //Version of the ACTIONRECORD bytecode
    //has sense only when isAction is true.
    SWFACTIONSCRIPT swfAS;

    //Parser function used to analyze the tag data.
    bool            (*tag_parser)(linput_t *li, ea_t start, ea_t end, bool hasLongHdr);
} SWFTAG;

bool header_parser (linput_t *li, ea_t start, ea_t end, bool isSWC);

// Default parser function for swf tags
// It comments the tag's RECORDHEADER
bool unk_tag_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr);

bool set_bgcolor_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr);

bool do_action_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr);

bool define_button_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr);

bool define_button2_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr);

bool place_obj2_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr);

bool place_obj3_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr);

// The sprite tag contains its own TAGs,
// just like a regular swf has. Unfortunatelly,
// I will be unable to define segments for
// the inner TAGs.
bool define_sprite_parser (linput_t *li, ea_t start_tag, ea_t end_tag, bool hasLongHdr_tag);

bool do_abc_parser (linput_t *li, ea_t start, ea_t end, bool hasLongHdr);

#define SWF_NAME_TAGS_NUMBER    100
//ordered array, element index should be the tag id
SWFTAG tags[SWF_NAME_TAGS_NUMBER] = {
    {"End",                             false,	AS2,	unk_tag_parser},	/* 0 */ 
    {"ShowFrame",	                    false,	AS2,	unk_tag_parser},	/* 1 */ 
    {"DefineShape",	                    false,	AS2,	unk_tag_parser},	/* 2 */ 
    {"FreeCharacter",	                false,	AS2,	unk_tag_parser},	/* 3 */ 
    {"PlaceObject",	                    false,	AS2,	unk_tag_parser},	/* 4 */ 
    {"RemoveObject",	                false,	AS2,	unk_tag_parser},	/* 5 */ 
    {"DefineBits",  	                false,	AS2,	unk_tag_parser},	/* 6 */ 
    {"DefineButton",	                true,	AS2,	define_button_parser},	/* 7 */ 
    {"JPEGTables",  	                false,	AS2,	unk_tag_parser},	/* 8 */ 
    {"SetBackgroundColor",	            false,	AS2,	set_bgcolor_parser},	/* 9 */ 
    {"DefineFont",      	            false,	AS2,	unk_tag_parser},	/* 10 */
    {"DefineText",      	            false,	AS2,	unk_tag_parser},	/* 11 */
    {"DoAction",	                    true,	AS2,	do_action_parser},	/* 12 */
    {"DefineFontInfo",  	            false,	AS2,	unk_tag_parser},	/* 13 */
    {"DefineSound",     	            false,	AS2,	unk_tag_parser},	/* 14 */
    {"StartSound",      	            false,	AS2,	unk_tag_parser},	/* 15 */
    {"Tag16",           	            false,	AS2,	unk_tag_parser},	/* 16 */
    {"DefineButtonSound",	            false,	AS2,	unk_tag_parser},	/* 17 */
    {"SoundStreamHead", 	            false,	AS2,	unk_tag_parser},	/* 18 */
    {"SoundStreamBlock",	            false,	AS2,	unk_tag_parser},	/* 19 */
    {"DefineBitsLossLess",	            false,	AS2,	unk_tag_parser},	/* 20 */
    {"DefineBitsJPEG2",	                false,	AS2,	unk_tag_parser},	/* 21 */
    {"DefineShape2",	                false,	AS2,	unk_tag_parser},	/* 22 */
    {"DefineButtonCxform",	            false,	AS2,	unk_tag_parser},	/* 23 */
    {"Protect",         	            false,	AS2,	unk_tag_parser},	/* 24 */
    {"Tag25",	                        false,	AS2,	unk_tag_parser},	/* 25 */
    {"PlaceObject2",	                false,	AS2,	place_obj2_parser},	/* 26 */
    {"Tag27",	                        false,	AS2,	unk_tag_parser},	/* 27 */
    {"RemoveObject2",	                false,	AS2,	unk_tag_parser},	/* 28 */
    {"Tag29",	                        false,	AS2,	unk_tag_parser},	/* 29 */
    {"Tag30",	                        false,	AS2,	unk_tag_parser},	/* 30 */
    {"FreeAll",	                        false,	AS2,	unk_tag_parser},	/* 31 */
    {"DefineShape3",	                false,	AS2,	unk_tag_parser},	/* 32 */
    {"DefineText2",     	            false,	AS2,	unk_tag_parser},	/* 33 */
    {"DefineButton2",   	            false,	AS2,	define_button2_parser},	/* 34 */
    {"DefineBitsJPEG3", 	            false,	AS2,	unk_tag_parser},	/* 35 */
    {"DefineBitsLossLess2",	            false,	AS2,	unk_tag_parser},	/* 36 */
    {"DefineEditText",  	            false,	AS2,	unk_tag_parser},	/* 37 */
    {"DefineMovie",     	            false,	AS2,	unk_tag_parser},	/* 38 */
    {"DefineSprite",	                false,	AS2,	define_sprite_parser},	/* 39 */
    {"NameCharacter",	                false,	AS2,	unk_tag_parser},	/* 40 */
    {"SerialNumber",    	            false,	AS2,	unk_tag_parser},	/* 41 */
    {"GeneratorText",   	            false,	AS2,	unk_tag_parser},	/* 42 */
    {"FrameLabel",  	                false,	AS2,	unk_tag_parser},	/* 43 */
    {"Tag44",	                        false,	AS2,	unk_tag_parser},	/* 44 */
    {"SoundStreamHead2",                false,	AS2,	unk_tag_parser},	/* 45 */
    {"DefineMorphShape",	            false,	AS2,	unk_tag_parser},	/* 46 */
    {"Tag47",	                        false,	AS2,	unk_tag_parser},	/* 47 */
    {"DefineFont2",     	            false,	AS2,	unk_tag_parser},	/* 48 */
    {"TemplateCommand", 	            false,	AS2,	unk_tag_parser},	/* 49 */
    {"Tag50",	                        false,	AS2,	unk_tag_parser},	/* 50 */
    {"Generator3",      	            false,	AS2,	unk_tag_parser},	/* 51 */
    {"ExternalFont",    	            false,	AS2,	unk_tag_parser},	/* 52 */
    {"Tag53",           	            false,	AS2,	unk_tag_parser},	/* 53 */
    {"Tag54",           	            false,	AS2,	unk_tag_parser},	/* 54 */
    {"Tag55",           	            false,	AS2,	unk_tag_parser},	/* 55 */
    {"ExportAssets",    	            false,	AS2,	unk_tag_parser},	/* 56 */
    {"ImportAssets",    	            false,	AS2,	unk_tag_parser},	/* 57 */
    {"EnableDebugger",  	            false,	AS2,	unk_tag_parser},	/* 58 */
    {"DoInitAction",    	            true,	AS2,	do_action_parser},	/* 59 */
    {"DefineVideoStream",	            false,	AS2,	unk_tag_parser},	/* 60 */
    {"VideoFrame",      	            false,	AS2,	unk_tag_parser},	/* 61 */
    {"DefineFontInfo2", 	            false,	AS2,	unk_tag_parser},	/* 62 */
    {"MX4",             	            false,	AS2,	unk_tag_parser},	/* 63 */
    {"EnableDebugger2",	                false,	AS2,	unk_tag_parser},	/* 64 */
    {"ScriptLimits",    	            false,	AS2,	unk_tag_parser},	/* 65 */
    {"SetTabIndex",     	            false,	AS2,	unk_tag_parser},	/* 66 */
    {"Tag67",                           false,	AS2,	unk_tag_parser},	/* 67 */
    {"Tag68",           	            false,	AS2,	unk_tag_parser},	/* 68 */
    {"FileAttributes",  	            false,	AS2,	unk_tag_parser},	/* 69 */
    {"PlaceObject3",    	            false,	AS2,	place_obj3_parser},	/* 70 */
    {"ImportAssets2",	                false,	AS2,	unk_tag_parser},	/* 71 */
    {"RawABC",	                        false,	AS2,	unk_tag_parser},	/* 72 */
    {"DefineFontAllignZones",	        false,	AS2,	unk_tag_parser},	/* 73 */
    {"CSMTextSettings", 	            false,	AS2,	unk_tag_parser},	/* 74 */
    {"DefineFont3",     	            false,	AS2,	unk_tag_parser},	/* 75 */
    {"SymbolClass",     	            false,	AS2,	unk_tag_parser},	/* 76 */
    {"Metadata",        	            false,	AS2,	unk_tag_parser},	/* 77 */
    {"DefineScalingGrid",	            false,	AS2,	unk_tag_parser},	/* 78 */
    {"Tag79",	                        false,	AS2,	unk_tag_parser},	/* 79 */
    {"Tag80",	                        false,	AS2,	unk_tag_parser},	/* 80 */
    {"Tag81",	                        false,	AS2,	unk_tag_parser},	/* 81 */
    {"DoABC",           	            true,	AS3,	do_abc_parser},	    /* 82 */
    {"DefineShape4",    	            false,	AS2,	unk_tag_parser},	/* 83 */
    {"DefineMorphShape2",	            false,	AS2,	unk_tag_parser},	/* 84 */
    {"Tag85",	                        false,	AS2,	unk_tag_parser},	/* 85 */
    {"DeleteSceneAndFrameLabelData",	false,	AS2,	unk_tag_parser},	/* 86 */
    {"DefineBinaryData",	            false,	AS2,	unk_tag_parser},	/* 87 */
    {"DefineFontName",	                false,	AS2,	unk_tag_parser},	/* 88 */
    {"StartSound2",     	            false,	AS2,	unk_tag_parser},	/* 89 */
    {"DefineBitsJPEG4",	                false,	AS2,	unk_tag_parser},	/* 90 */
    {"DefineFont4",     	            false,	AS2,	unk_tag_parser},	/* 91 */
    {"Tag92",	                        false,	AS2,	unk_tag_parser},	/* 92 */
    {"Tag93",	                        false,	AS2,	unk_tag_parser},	/* 93 */
    {"Tag94",	                        false,	AS2,	unk_tag_parser},	/* 94 */
    {"Tag95",	                        false,	AS2,	unk_tag_parser},	/* 95 */
    {"Tag96",	                        false,	AS2,	unk_tag_parser},	/* 96 */
    {"Tag97",	                        false,	AS2,	unk_tag_parser},	/* 97 */
    {"Tag98",	                        false,	AS2,	unk_tag_parser},	/* 98 */
    {"Tag99",	                        false,	AS2,	unk_tag_parser} 	/* 99 */
};

#endif