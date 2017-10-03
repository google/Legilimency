# Legilimency
#### A Memory Research Platform for iOS

Written and maintained by Gal Beniamini, <laginimaineb@google.com>

Copyright 2017 Google Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
      
#### Disclaimer

This is not an official Google product.

#### Usage

Legilimency is a memory exploration framework allowing navigation of the kernel's
data structures from a python scripting environment. It connects to a server on
the target device implementing the Legilimency protocol (see "Protocol"), and
issues subsequent memory access requests to the resident stub on the device.

To use Legilimency, run an exploit stub on the target implementing the server
protocol, then connect to the target using:

 `python memshell.py <TARGET_IP>`

Note that the provided implementation in memshell.py is left empty. After connecting to
the client you may fill in the code under "memshell.py" to utilise the provided classes
and explore the kernel's memory.

#### Protocol

Legilimency uses a basic binary protocol to communicate with the server stub. All
data types used are encoded in little-endian byte order. The protocol after a successful
TCP connection is made to the server. Subsequently, the server sends a QWORD containing
the kernel's KASLR slide.

After the connection is made, the client may issue requests to the server. Each request is
prefixed by a single byte representing the command code, followed by the request's contents.

The following commands are supported:

 - Read Command - Command Code 'r':
  
        Reads a single 128-bit value from the kernel's virtual address space.
        
        All arguments and return values are XORed with a mask of 0xFF bytes.
        
        Client Request : 'r' || <64-bit Kernel VA>
        Server Response: <128-bit Obfuscated Data>
        

- Read Chunk Command - Command Code 'c':
  
        Reads a chunk of contiguous data from the kernel's virtual address space. 
        
        All arguments and return values are XORed with a mask of 0xFF bytes.
        
        Client Request : 'c' || <64-bit Kernel VA> || <64-bit unsigned size>
        Server Response: <Obfuscated Data Chunk>
        
- Write Command - Command Code 'w':
  
        Writes a single 64-bit value to the kernel's virtual address space. 
        
        All arguments are XORed with a mask of 0xFF bytes.
        
        Client Request : 'w' || <64-bit Kernel VA> || <64-bit value>
        Server Response: <64-bit 0>
                  
- Execute Command - Command Code 'x':
  
        Executes a given function in the kernel's virtual address space, taking two arguments.
        
        All arguments are XORed with a mask of 0xFF bytes.
        
        Client Request : 'x' || <64-bit Kernel Function VA> || <64-bit arg1> || <64-bit arg2>
        Server Response: <64-bit 0>
        
- Data Race Command - Command Code 'f':
  
        Executes a data race by writing the given 64-bit value to the given kernel virtual address,
        then immediately writing the original value back to that address.
        
        All arguments are XORed with a mask of 0xFF bytes.
        
        Client Request : 'f' || <64-bit Kernel Function VA> || <64-bit value>
        Server Response: <64-bit 0>
        
