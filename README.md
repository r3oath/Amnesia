Amnesia
=======

Copyright (c) 2013 Tristan Strathearn (r3oath@gmail.com)

### What is it?

![amnesia](http://www.r3oath.com/wp-content/uploads/2013/08/amnesia.jpg)

Introducing Amnesia, a Layer 1 binary analysis system. Amnesia was designed for the initial analysis of unknown an EXE or DLL. It offers you the ability to view and search for strings, imports, exports, metadata, checksums and to even disassemble the code. This helpful for getting an overview of the file before diving in deeper with a debugger or a dynamic analysis framework.

![metadata](http://www.r3oath.com/wp-content/uploads/2013/08/metadata.jpg)

I've designed the menu and interface to be as user friendly as possible and developed a built in tool similar to Less (on Linux) or More (on Windows) for dealing with large amounts of output. This makes it easy to scroll through the dump and even save it to file at any time if you wish to analyze it further outside of Amnesia.

![imports](http://www.r3oath.com/wp-content/uploads/2013/08/imports.jpg)

Using the disassembly option you can quickly see if a subject looks packed (or check the metadata section) or standard (look for typical compiler Prolog's etc). I've also added an option in the Exports section to generate Visual Studio #Pragma comments for DLL forwarders. This is useful if you're wanting to overwrite an existing DLL's functionality for only a few functions, and forward the rest to the original, renamed DLL.

![disas](http://www.r3oath.com/wp-content/uploads/2013/08/disas.jpg)

I've embedded a short overview video if you'd like to see the functionality before downloading Amnesia.

http://www.youtube.com/watch?v=1Yzj0b3qF4o

Enjoy ;)
