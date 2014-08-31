DESCRIPTION:

Shockwave Flash is a very common and widely used file format that,
unfortunatelly, has not been able to make its way into IDA's
recognized file formats. The increasing numbers of grayware and
malware SWF files require security researchers to disassemble and
analyse such files and IDA is again an ideal tool to use.

The 2 plugins present in this archive will enable IDA to parse SWF
files, load all SWF tags as segments for fast search and retrieval, 
parse all tags that can potentially contain ActionScript2 code, 
discover all such code(a dedicated processor module has been written for it)
and even name the event functions acording to event handled in it
(eg. OnInitialize).

Due to the nature of ActionScript2 code execution, this can be crafted
to spread through several tags. Because of this "feature" many static 
analisys tools are not able to fully disassemble all ActionScript code.
This is no longer the case when using these plugins.


CONTENTS:

swf_as2.w32 is a processor module that will disassemble ActionScript2
code. 

swfldr.ldw is a loader module that will map Adobe Flash files into
IDA's database, adnotate/comment interesting tags, discovere the code
islands and add them as entry points.

ida.int is an updated version of the existing ida.int file that includes
the ActionScript2 instruction comments.

The 2 plugins are designed to help analyzing malicious Flash files.
The curent verision of the loader does not support parsing of DoABC
tags(ActionScript3 container) as this feature is still under development.

AUTHOR:

Marian RADU <marianra@microsoft.com>


HOW TO USE:

Just copy the contents of the "binaries" folder to %programfiles%\IDA


SAMPLE FILES TO ANALYZE:

This archive also contains 4 sample files that can be loaded in IDA
using these 2 plugins. EDITED BY HEXRAYS: removed some malicious sample files


