# C# Source Code Anti-Plagiarism Technique

This repository contains the source code of an anti-plagiarism technique for C# applications which was implemented as a master thesis project. 
The source code consists of a C# project named *RouterProject* which has to be included as project reference through VisualStudio for each project that has at least one class accessing its functionalities. 

The general idea behind the technique is briefly summarised below, please refer to the original document for further details. 

Developer has to replace original function calls with correspondent Router *forwardCall* and then run the Router initialization step. 
During such step, each replaced function call information like destination classname, function names but also its parameters are encrypted and *solved hashes* computed over new source files containing encrypted info. Encryption and hashing details can be found on the original document, the proposed technique uses AES-256 with a runtime computed symmetric encryption key and SHA-2 family for hash values computation. By encrypting such information and by checking hashes at runtime, the Router prevent source code modification, which in turn prevent a trial-and-error approach for guessing the original function calls and then enabling plagiarism for such code. 

Once the initialization step terminates, several Base-64 strings declarations (C# syntax) are printed to standard output. Those declarations must replace those with the same name declared by default at the very first lines of the Router.cs class. Once done, the project with encrypted source code have to be re-compiled.
Finally, as the Router code could be easily retrieved through a .NET decompiler it must be obfuscated (e.g. using [SmartAssembly](https://www.red-gate.com/products/dotnet-development/smartassembly/)) and then the application should be released.

Every kind of protection which is applied at compilation time can only encrypts data available at that time, therefore function calls with dynamic parameters cannot be fully secured. In other words, dynamic parameters cannot be secured in this way while those whose value is known at compile time can be encrypted. Another disadvantage of such implementation is the [*ilspycmd*](https://www.nuget.org/packages/ilspycmd/) external dependency which restricts implementation usage to Desktop applications based on .NET Core or onto the .NET Framework.


Such implementation was tested on [KeePass](https://keepass.info/) (v2.48) one of the most used open-source password manager.

KeePass v2.48 original source code can be downloaded [here](https://sourceforge.net/projects/keepass/files/KeePass%202.x/2.48/) while the corresponding modified source code is [keepass-modified-sources](https://github.com/msc-antiplag/keepass-modified-sources). <br /> 
The RouterProject can be downloaded [here](https://github.com/msc-antiplag/RouterProject).
