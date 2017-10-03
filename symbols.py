#   Legilimency - Memory Analysis Framework for iOS
#   --------------------------------------
#
#   Written and maintained by Gal Beniamini <laginimaineb@google.com>
#
#   Copyright 2017 Google Inc. All Rights Reserved.
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

#----------------------------Kernel Symbols----------------------------#

#The PCIe Object's VTable
PCIE_OBJECT_VTABLE = 0xFFFFFFF006FD5B30

#The bounds for the zone_map ranges
ZONE_MAP_MIN_ADDRESS = 0xFFFFFFF00759A368
ZONE_MAP_MAX_ADDRESS = 0xFFFFFFF00759A370

#The bounds for the zone metadata regions
ZONE_METADATA_REGION_MIN = 0xFFFFFFF00759A378 
ZONE_METADATA_REGION_MAX = 0xFFFFFFF00759A380

#Pointer to the maximal size of a kalloc cache
KALLOC_MAX_PREROUND = 0xFFFFFFF007582FE0

#Pointer to the beginning of the zone array
K_ZONE = 0xFFFFFFF007583170

#Pointer to the array of zone sizes
K_ZONE_SIZES = 0xFFFFFFF00700863C

#The physical and virtual bases of the kernel
G_PHYS_BASE = 0xFFFFFFF0075F6080
G_VIRT_BASE = 0xFFFFFFF0075F6088

#The pidhash field in the kernel
PIDHASH = 0xFFFFFFF0075F0488

#The pidhashtbl field in the kernel
PIDHASHTBL = 0xFFFFFFF0075F0490

#The address of the kernel's pmap structure
KERNEL_PMAP = 0xFFFFFFF0075CE878

#The address of the kernel's task_t structure
KERNEL_TASK = 0xFFFFFFF0075F6050

#The address of the kernproc structure
KERNPROC = 0xFFFFFFF0075F60E0

#The _current_task function
CURRENT_TASK = 0xFFFFFFF00711AA84

#The address of a "MOV X0, #0; BX LR;" gadget
RET_ZERO = 0xFFFFFFF0070F013C

#The address of a gadget used to execute a function in a vtable
#and store its value relative to the object. Using this function
#we can build an execute primitive that returns the value of the 
#executed function.
EXEC_FUNCTION_GADGET = 0xFFFFFFF0065B8044

#A junk address in the BSS which we slightly corrupt in various stages.
#Randomly picked - seems not to have any adverse effects when written to.
JUNK_ADDRESS = 0xFFFFFFF007587C50

#A gadget used to write a 32-bit value:
#  STR W0, [X1]
#  RET 
WRITE_32BIT_GADGET = 0xFFFFFFF0063E43FC

#A gadget used to read a 32-bit value:
#  LDR W8, [X0,#0xA4]
#  STR W8, [X1,#4]
#  RET
READ_32BIT_GADGET = 0xFFFFFFF006D395D8

#----------------------Broadcom Wi-Fi SoC Symbols----------------------#

#The D2H DMA object's address.
D2H_OBJ_ADDR = 0x1F6810

#The address of the heap's freelist.
FREELIST_ADDR = 0x16C954

#The adderss of an "unoccupied" location into which the hook in written.
HOOK_ADDRESS = 0x210900

#The dma64_txfast function
DMA_FUNC = 0x16E5C0

#The IOCTL function
IOCTL_FUNC = 0x181420

#The address of the RRM context object
RRM_CTX = 0x20ADE8

#Pointer to the list of disallowed heap ranges (verified in the "free" function)
DISALLOWED_HEAP_RANGES_PTR = 0x1B8488

#The location of the DWORD denoting the number of allowed heap ranges
ALLOWED_HEAP_RANGES_COUNT_PTR = 0x1B84D0

#The address of the allowed heap ranges array
ALLOWED_HEAP_RANGES_ARRAY_ADDR = 0x1B8490

#Address of the log status array (indicating which ELxx logs are printed to the console)
LOG_STATUS_ARRAY_PTR = 0x1609E4

#The "wl hc" function pointer address
WL_HC_PTR = 0x2078B0
