/*
*  Interactive disassembler (IDA).
*  Adobe Flash ActionScript2 processor module
*  Marian RADU <marianra@microsoft.com>
*/

#include <ida.hpp>
#include <idp.hpp>
#include "ins.hpp"

instruc_t Instructions[] = {
    { "",                    0},  // Unknown Operation

    { "end",                 CF_STOP}, //marks the end of the actions tag

    /* v3 actions */
    { "nextframe",           0}, //Go to the next frame.
    { "prevframe",           0}, //Go to the previous frame.
    { "play",                0}, //Start playing at the current frame.
    { "stop",                0}, //Stop playing at the current frame.
    { "togglequality",       0}, //Toggle the display between high and low quality.
    { "stopsounds",          0}, //Stop all sounds playing
    { "gotoframe",           CF_USE1}, //Go to the specified frame.
    { "geturl",              CF_USE1|CF_USE2}, //Get the specified URL.
    { "waitforframe",        CF_USE1|CF_USE2}, //Wait for the specified frame.
    { "settarget",           CF_USE1}, //Change the context of subsequent actions to a named object.
    { "gotolabel",           CF_USE1}, //Go to the frame with the specified label.

    /* v4 actions */
    { "add",                 0}, //adds two numbers and pushes the result back to the stack.
    { "subtract",            0}, //subtracts two numbers and pushes the result back to the stack.
    { "multiply",            0}, //multiplies two numbers and pushes the result back to the stack.
    { "divide",              0}, //divides two numbers and pushes the result back to the stack.
    { "equals",              0}, //tests two numbers for equality.
    { "lessthan",            0}, //tests if a number is less than another number.
    { "and",                 0}, //performs a logical AND of two numbers.
    { "or",                  0}, //performs a logical OR of two numbers.
    { "not",                 0}, //performs a logical NOT of a number.
    { "stringeq",            0}, //tests two strings for equality.
    { "stringlength",        0}, //computes the length of a string. 
    { "stringextract",       0}, //extracts a substring from a string.
    { "pop",                 0}, //pops a value from the stack and discards it.
    { "toint",               0}, //converts a value to an integer.
    { "getvariable",         0}, //Gets a variable's value.
    { "setvariable",         0}, //Sets a variable's value.
    { "settarget2",          0}, //Sets the current context and is stack based. 
    { "stringconcat",        0}, //Concatenates two strings.
    { "getproperty",         0}, //Gets a file property.
    { "setproperty",         0}, //Sets a file property.
    { "clonesprite",         0}, //Clones a sprite.
    { "removesprite",        0}, //Removes a clone sprite.
    { "trace",               0}, //Sends a debugging output string.
    { "startdragmovie",      0}, //Starts dragging a movie clip.
    { "stopdragmovie",       0}, //Ends the drag operation in progress, if any.
    { "stringlessthan",      0}, //tests to see if a string is less than another string
    { "random",              0}, //calculates a random number.
    { "mbstringlength",      0}, //computes the length of a string and is multi-byte aware. 
    { "chartoascii",         0}, //converts character code to ASCII.
    { "asciitochar",         0}, //converts a value to an ASCII character code.
    { "gettimer",            0}, //reports the milliseconds since Adobe Flash Player started.
    { "mbstringextract",     0}, //extracts a substring from a string and is multi-byte aware
    { "mbchartoascii",       0}, //converts character code to ASCII and is multi-byte aware.
    { "mbasciitocahr",       0}, //converts ASCII to character code and is multi-byte aware.
    { "waitforframe2",       CF_USE1}, //waits for a frame to be loaded and is stack based.
    { "push",                CF_USE1}, //pushes one or more values to the stack. 
    { "jump",                CF_USE1}, //creates an unconditional branch.
    { "geturl2",             CF_USE1|CF_USE2|CF_USE3}, //Gets an url. 
    { "if",                  CF_USE1}, //creates a conditional test and branch.
    { "callframe",           CF_CALL}, //Calls a subroutine.
    { "gotoframe2",          CF_USE1}, //Goes to a frame and is stack based.

    /* v5 actions */
    { "delete",              0}, //deletes a named property from a ScriptObject. 
    { "delete2",             0}, //deletes a named property.
    { "definelocal",         0}, //defines a local variable and sets its value. 
    { "call",                CF_CALL}, //executes a function.
    { "return",              0}, //forces the return item to be pushed off the stack and returned.
    { "modulo",              0}, //calculates x modulo y.
    { "newobject",           0}, //invokes a constructor function.
    { "var",                 0}, //defines a local variable without setting its value.
    { "initarray",           0}, //initializes an array in a ScriptObject and is similar to ActionInitObject.
    { "initobject",          0}, //initializes an object and is similar to ActionInitArray.
    { "typeof",              0}, //pushes the object type to the stack.
    { "targetpath",          0}, //the object's target path is pushed on the stack in dot notation.
    { "enumerate",           0}, //obtains the names of all slots in use in an ActionScript object.
    { "add2",                0}, //similar to ActionAdd, but performs the addition differently, according to the data types of the arguments.
    { "less2",               0}, //calculates whether arg1 is less than arg2 and pushes a Boolean return value to the stack.
    { "equals2",             0}, //similar to ActionEquals, but ActionEquals2 knows about types. 
    { "tonumber",            0}, //Converts the object on the top of the stack into a number, and pushes the number back to the stack.
    { "tostring",            0}, //converts the object on the top of the stack into a String, and pushes the string back to the stack.
    { "pushduplicate",       0}, //pushes a duplicate of top of stack (the current return value) to the stack.
    { "stackswap",           0}, //swaps the top two ScriptAtoms on the stack.
    { "getmember",           0}, //retrieves a named property from an object, and pushes the value of the property onto the stack.
    { "setmember",           0}, //sets a property of an object.
    { "increment",           0}, //pops a value from the stack, converts it to number type, increments it by 1, and pushes it back to the stack.
    { "decrement",           0}, //pops a value from the stack, converts it to number type, decrements it by 1, and pushes it back to the stack.
    { "callmethod",          CF_CALL}, //pushes a method (function) call onto the stack, similar to ActionNewMethod.
    { "newmethod",           0}, //invokes a constructor function to create a new object.
    { "bitwiseand",          0}, //performs a bitwise AND
    { "bitwiseor",           0}, //performs a bitwise OR
    { "bitwisexor",          0}, //performs a bitwise XOR
    { "shiftleft",           CF_SHFT}, //shifts to the left by the shift count
    { "shiftright",          CF_SHFT}, //shifts to the right by the shift count
    { "shiftright2",         CF_SHFT}, //shifts to the right by the shift count
    { "storeregister",       CF_USE1}, //reads the next object from the stack (without popping it) and stores it in one of four registers.
    { "constantpool",        CF_USE1}, //reates a new constant pool, and replaces the old constant pool if one already exists.
    { "with",                CF_USE1}, //Defines a With block of script.
    { "definefunction",      CF_USE1|CF_USE2}, //defines a function with a given name and body size.

    /* v6 actions */
    { "instanceof",          0}, //implements the ActionScript instanceof() operator.
    { "enumerate2",          0}, //similar to ActionEnumerate, but uses a stack argument of object type rather than using a string to specify its name
    { "strictequals",        0}, //similar to ActionEquals2, but the two arguments must be of the same type in order to be considered equal
    { "greater",             0}, //is the exact opposite of ActionLess2.
    { "stringgreater",       0}, //is the exact opposite of ActionStringLess.
    { "strictmode",          0}, //sets the strict mode

    /* v7 actions */
    { "cast",                0}, //implements the ActionScript cast operator
    { "implements",          0}, //implements the ActionScript implements keyword.
    { "extends",             0}, //implements the ActionScript extends keyword
    { "definefunction2",     CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5|CF_USE6}, //similar to ActionDefineFunction, with additional features
    { "try",                 CF_USE1|CF_USE2|CF_USE3|CF_USE4}, //defines handlers for exceptional conditions, implementing the ActionScript try, catch, and finally keywords.
    { "throw",               0}, // implements the ActionScript throw keyword.

    /* FlashLite */
    { "fscommand2",          0}
};

#ifdef __BORLANDC__
#if sizeof(Instructions)/sizeof(Instructions[0]) != SWFACTION_LAST
#error          No match:  sizeof(AWF_Actions) !!!
#endif
#endif
