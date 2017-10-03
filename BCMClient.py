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

from MemClient import MemClient, qword_at
from defs import *
from symbols import *
from kalloc import *
from AppleBCMWLANPCIeSubmissionRing import AppleBCMWLANPCIeSubmissionRing
from AppleBCMWLANPCIeCompletionRing import AppleBCMWLANPCIeCompletionRing
from DART import DART
import time, struct

#The size of the allocation for the PCIe object
PCIE_OBJECT_ALLOCATION_SIZE = 3824

#The offset of the internal object representing SoC memory access within the PCIe object
CHIP_INTERNAL_OBJECT_OFFSET = 896

#The offset of the TCM field within the internal object
TCM_OFFSET = 144

#The offset of the RAM offset field in the internal object
RAM_OFFSET_OFFSET = 132

#The offset of the RAM size field in the internal object
RAM_SIZE_OFFSET = 136

#The size of the embedded firmware log array
LOG_ARRAY_SIZE = 80

#The offset of the IOMapper instance in the PCIe object
IO_MAPPER_OFFSET = 808

#The offset of the IOVMAllocator instance in the IOMapper instance
IO_VM_ALLOCATOR_OFFSET = 240

#The offset of the AppleS5L8960XDART instance in the IOVMAllocator instance
SL_DART_OFFSET = 24

#The offset of the resource map field in the PCIe object
RESOURCE_MAP_OFFSET = 696

#The offset of the resource array field in the resource map instance
RESOURCE_ARRAY_OFFSET = 24

#The offset of the max resource ID field in the resource map instance
MAX_RESOURCE_ID_OFFSET = 20

#The offset of the resource mapping object within the resource instance
MAPPING_OBJ_OFFSET = 32

#The offset of the resource data offset field in the resource instance
RESOURCE_DATA_OFFSET_OFFSET = 40

#The offset of the resource data array field in the resource instance
RESOURCE_DATA_ARRAY_OFFSET = 72

#The size of an entry in the resource data array
RESOURCE_ENTRY_SIZE = 16

#The offset of the resource offset field in the resource instance
RESOURCE_OFFSET_OFFSET = 64

#The offset of the resource length field in the resource instance
RESOURCE_LENGTH_OFFSET = 68

#The offset of the mbuf field in the resource instance
RESOURCE_MBUF_OFFSET = 56

#The time, in seconds, to wait when polling for a code chunk's hook on wl_hc to complete
HOOK_POLL_DELAY = 0.5

#The time, in seconds, to wait when polling the firmware for a crash
REBOOT_POLL_DELAY = 0.1

class BCMClient(object):
    """
    This client is used to control the BCM Wi-Fi SoC by manipulating it's TCM.
    """

    def __init__(self, client):
        """
        Creates a new client, using the underlying MemShell client. Automatically
        locates the PCIe object in the kalloc zones and extracts the TCM's location.
        """

        self.client = client
        self.pcie_obj = find_object_by_vtable(self.client, PCIE_OBJECT_VTABLE + self.client.slide(), PCIE_OBJECT_ALLOCATION_SIZE)
        internal_object = self.client.read64(self.pcie_obj + CHIP_INTERNAL_OBJECT_OFFSET)
        self.tcm = self.client.read64(internal_object + TCM_OFFSET)
        self.ram_offset = self.client.read32(internal_object + RAM_OFFSET_OFFSET)
        self.ram_size = self.client.read32(internal_object + RAM_SIZE_OFFSET)
   
    def get_pcie_obj(self):
        """
        Returns the address of the PCIe object.
        """

        return self.pcie_obj

    def fw_check_range(self, fw_addr, size):
        """
        Checks that the given address range falls within the firmware's TCM, and raises
        an exception otherwise.
        """

        if not (self.ram_offset <= fw_addr <= (self.ram_offset + self.ram_size)) or \
           not (self.ram_offset <= (fw_addr + size) <= (self.ram_offset + self.ram_size)):
           raise Exception("Illegal FW read range: [%08X,%08X]" % (fw_addr, fw_addr + size))
        
    def fw_read(self, fw_addr, size):
        """
        Reads an arbitrarily large block from the firmware's TCM.
        """

        self.fw_check_range(fw_addr, size)
        return self.client.read(self.tcm + fw_addr - self.ram_offset, size)

    def fw_read128(self, fw_addr):
        """
        Reads a 128-bit value from the firmware's TCM.
        """

        self.fw_check_range(fw_addr, struct.calcsize("QQ"))
        return self.client.read128(self.tcm + fw_addr - self.ram_offset)

    def fw_read64(self, fw_addr):
        """
        Reads a 64-bit value from the firmware's TCM.
        """

        self.fw_check_range(fw_addr, QWORD_SIZE)
        return self.client.read64(self.tcm + fw_addr - self.ram_offset)

    def fw_read32(self, fw_addr):
        """
        Reads a 32-bit value from the firmware's TCM.
        """

        self.fw_check_range(fw_addr, DWORD_SIZE)
        return self.client.read32(self.tcm + fw_addr - self.ram_offset)

    def fw_write64(self, fw_addr, val):
        """
        Writes a 64-bit value to the firmware's TCM.
        """

        self.fw_check_range(fw_addr, QWORD_SIZE)
        self.client.write64(self.tcm + fw_addr - self.ram_offset, val)

    def fw_write32(self, fw_addr, val):
        """
        Writes a 32-bit value to the firmware's TCM.
        """

        self.fw_check_range(fw_addr, DWORD_SIZE)
        self.client.write32(self.tcm + fw_addr - self.ram_offset, val)

    def fw_write8(self, fw_addr, val):
        """
        Writes an 8-bit value to the firmware's TCM.
        """

        #Ensuring this is a valid range (including trailing bits after the last byte read)
        dword_off = fw_addr % DWORD_SIZE
        aligned_addr = fw_addr - dword_off
        self.fw_check_range(aligned_addr, DWORD_SIZE)

        #Switching the previous byte to the target one
        prev_val = self.fw_read32(aligned_addr)
        val_bytes = [b for b in struct.pack("<I", prev_val)]
        val_bytes[dword_off] = chr(val)

        #Updating the 32-bit word at the aligned address
        new_val = struct.unpack("<I", "".join(val_bytes))[0]
        self.fw_write32(aligned_addr, new_val)
    
    def read_ram(self):
        """
        Reads the firmware's entire RAM.
        """

        return self.fw_read(self.ram_offset, self.ram_size)

    def execute_chunk(self, code_chunk, is_thumb=True):
        """
        Executes the given code chunk on the Wi-Fi firmare.
        """
        
        #Writing the chunk's contents to some unused memory in the heap's head
        code_chunk += "\x00" * (QWORD_SIZE - (len(code_chunk) % QWORD_SIZE)) #Pad to QWORD
        hook_ptr = HOOK_ADDRESS + (1 if is_thumb else 0)
        for i in range(0, len(code_chunk), QWORD_SIZE):
            self.fw_write64(HOOK_ADDRESS + i, struct.unpack("<Q", code_chunk[i:i+QWORD_SIZE])[0])
        
        #Hook the WL_HC pointer
        self.fw_write32(WL_HC_PTR, hook_ptr)

        #Wait for the chunk to unhook the pointer (signaling completion)
        while self.fw_read32(WL_HC_PTR) == hook_ptr:
            time.sleep(HOOK_POLL_DELAY)  

    def reboot_firmware(self):
        """
        Reboots the firmware by corrupting a periodically executed function pointer
        """

        self.fw_write32(WL_HC_PTR, GARBAGE_VALUE)
        while self.fw_read32(WL_HC_PTR) == GARBAGE_VALUE:
            time.sleep(REBOOT_POLL_DELAY)

    def get_allowed_heap_ranges(self):
        """
        Returns the list of allowed heap ranges
        """

        num_descs = self.fw_read32(ALLOWED_HEAP_RANGES_COUNT_PTR)
        ranges = []
        for i in range(0, num_descs):
            range_base = self.fw_read32(ALLOWED_HEAP_RANGES_ARRAY_ADDR + i*(2*DWORD_SIZE) + DWORD_SIZE)
            range_size = self.fw_read32(ALLOWED_HEAP_RANGES_ARRAY_ADDR + i*(2*DWORD_SIZE))
            ranges.append((range_base, range_base+range_size))
        return ranges

    def get_disallowed_heap_ranges(self):
        """
        Returns the list of disallowed heap ranges
        """

        curr = DISALLOWED_HEAP_RANGES_PTR
        ranges = []
        while curr != 0:
            next_addr = self.fw_read32(curr + DWORD_SIZE)
            if next_addr == 0:
                break
            size = self.fw_read32(next_addr)
            ranges.append((next_addr, next_addr + size))
            curr = next_addr
        return ranges

    def get_enabled_log_tags(self):
        """
        Returns the list of enabled log tags
        """

        log_status_array = self.fw_read32(LOG_STATUS_ARRAY_PTR) 
        log_status_bytes = self.fw_read(log_status_array, LOG_ARRAY_SIZE)
        return [i for i in range(0, LOG_ARRAY_SIZE) if ord(log_status_bytes[i]) & 0x40]

    def enable_log(self, tag):
        """
        Enables the given log tag in the logging configuration array
        """

        log_status_array = self.fw_read32(LOG_STATUS_ARRAY_PTR)
        self.fw_write8(log_status_array + tag, 0xC0)

    def disable_log(self, tag):
        """
        Disables the given log tag in the logging configuration array
        """

        log_status_array = self.fw_read32(LOG_STATUS_ARRAY_PTR)
        self.fw_write8(log_status_array + tag, 0x00)

    def get_resource(self, resource_array_data, resource_id):
        """
        Returns a tuple containing the resource information for the resource with the given ID, 
        or None if no such resource exists. The tuple contains the following information:
            (resource_addr, data_addr, offset, length, mbuf, addr_ptr_offset)
        """

        #Getting the resource object
        resource = qword_at(resource_array_data, resource_id)
        if resource == 0:
            return None
        
        #Retrieving the data address by following the mappings
        data_addr = 0 
        mapping_obj = self.client.read64(resource + MAPPING_OBJ_OFFSET)
        data_off = self.client.read32(resource + RESOURCE_DATA_OFFSET_OFFSET)
        if mapping_obj != 0:
            data_array_base = self.client.read64(mapping_obj + RESOURCE_DATA_ARRAY_OFFSET)
            if data_array_base != 0:
                data_addr = self.client.read64(data_array_base + RESOURCE_ENTRY_SIZE * data_off) 
        
        return (resource,
                data_addr,
                self.client.read32(resource + RESOURCE_OFFSET_OFFSET),
                self.client.read32(resource + RESOURCE_LENGTH_OFFSET),
                self.client.read64(resource + RESOURCE_MBUF_OFFSET),
                data_off) 
 
    def get_resources(self, verbose=False):
        """
        Returns the information for each of the "resource IDs" currently in the resource array
        """
        
        #Finding the resource array and size
        pcie_obj = self.get_pcie_obj()
        res_map = self.client.read64(pcie_obj + RESOURCE_MAP_OFFSET)
        resource_array = self.client.read64(res_map + RESOURCE_ARRAY_OFFSET)
        max_resource_id = (self.client.read32(res_map + MAX_RESOURCE_ID_OFFSET) & 0xFFFF)
        if verbose:
            print "Resource Array: %16X, Max Resource ID: %d" % (resource_array, max_resource_id)

        #Dumping all resources
        resource_array_data = self.client.read(resource_array, max_resource_id * QWORD_SIZE)
        resources = [self.get_resource(resource_array_data, res_id) for res_id in range(0, max_resource_id)]
        return filter(lambda x: x is not None, resources)

    def get_dart(self, verbose=True):
        """
        Finds the DART instance associated with the Broadcom Wi-Fi chip
        """ 

        pcie_obj = self.get_pcie_obj()
        iomapper_ptr = self.client.read64(pcie_obj + IO_MAPPER_OFFSET)
        io_vm_allocator = self.client.read64(iomapper_ptr + IO_VM_ALLOCATOR_OFFSET)
        sl_dart = self.client.read64(io_vm_allocator + SL_DART_OFFSET)
        return DART(self.client, sl_dart, verbose)
 
    def read_console(self):
        """
        Reads the firmware's console.
        """

        #Getting the firmware-resident log address
        pciedev_shared_t_addr = self.fw_read32(self.ram_offset + self.ram_size - DWORD_SIZE)
        console_addr = self.fw_read32(pciedev_shared_t_addr + 5*DWORD_SIZE)
        log_addr = self.fw_read32(console_addr + 2*DWORD_SIZE)
        log_size = self.fw_read32(console_addr + 3*DWORD_SIZE)

        #Reading unaligned slack
        log = ""
        while log_addr % 16 != 0:
            log_addr += DWORD_SIZE
            log_size -= DWORD_SIZE
            log += struct.pack("<I", self.fw_read32(log_addr))

        #Reading the rest
        log_size -= log_size % 16
        log += self.fw_read(log_addr, log_size)
        return log

    def read_freelist(self):
        """
        Reads the heap's freelist, returns a list of the form: [(chunk_addr, chunk_size),...]
        """

        freelist_head = self.fw_read32(FREELIST_ADDR)
        curr = freelist_head
        freelist = []
        while curr != 0:
            freelist.append((curr, self.fw_read32(curr)))
            curr = self.fw_read32(curr + DWORD_SIZE)
            if curr > (self.ram_offset + self.ram_size):
                freelist.append((curr, GARBAGE_VALUE))
                break
        return freelist

    def dump_freelist(self):
        """
        Prints each freechunk in the heap.
        """

        freelist = self.read_freelist()
        print "->".join(["(A %06X | S %05X)" % (addr, size) for (addr, size) in freelist])

    def hook(self, function_address, hook_content, hook_address):
        """
        Inserts a hook onto the given function. The hook is placed at the given
        address (so please make sure that it isn't occupied - e.g., near the top
        of the heap).
        """

        #Writing a THUMB2 wide branch to our hook
        preamble   = self.fw_read32(function_address)
        next_word  = self.fw_read32(function_address + DWORD_SIZE)

        branch_to_hook = self.encode_thumb2_wide_branch(function_address, hook_address)
        branch_back    = self.encode_thumb2_wide_branch(hook_address + len(hook_content) + DWORD_SIZE, function_address + DWORD_SIZE)

        #Writing the hook's contents
        for i in range(0, len(hook_content), QWORD_SIZE):
            self.fw_write64(hook_address + i, struct.unpack("<Q", hook_content[i:i+QWORD_SIZE])[0])

        #Writing the opcode + branch to the end of the hook
        self.fw_write64(hook_address + len(hook_content),
                        struct.unpack("<Q", struct.pack("<I", preamble) + branch_back)[0])

        #Finally, inserting the hook itself
        self.fw_write64(function_address, struct.unpack("<Q", branch_to_hook + struct.pack("<I", next_word))[0])

    def inject_frame(self, frame, num_injections=1):
        """
        Injects the given frame directly from the firmware into the host,
        repeating the given number of times.
        """

        injection_chunk = open("code_chunks/send_frame/chunk.bin", "rb").read()
        injection_chunk = injection_chunk.replace(struct.pack("<I", 0xF12A515E), struct.pack("<I", len(frame)))
        injection_chunk = injection_chunk.replace(struct.pack("<I", 0xBEEFBEEF), struct.pack("<I", num_injections))
        injection_chunk = injection_chunk.replace(1024*"\xAB", frame + ("\xAB" * (1024 - len(frame))))
        self.execute_chunk(injection_chunk)

    def dma_d2h(self, host_addr, dma_contents):
        """
        Performs a DMA operation from the firmware to IO-Space (D2H). 
        """

        code_chunk = open("code_chunks/dma_d2h/chunk.bin", "rb").read()
        code_chunk = code_chunk.replace(struct.pack("<I", 0xBEEF0101), struct.pack("<I", len(dma_contents)))
        code_chunk = code_chunk.replace(struct.pack("<I", 0xBEEF0202), struct.pack("<I", host_addr & 0xFFFFFFFF))
        code_chunk = code_chunk.replace(struct.pack("<I", 0xBEEF0303), struct.pack("<I", (host_addr >> 32) & 0xFFFFFFFF))
        code_chunk = code_chunk.replace(128*"\xAB", dma_contents + ("\xAB" * (128 - len(dma_contents))))
        self.execute_chunk(code_chunk)

    def encode_thumb2_wide_branch(self, from_addr, to_addr):
        """
        Encodes an unconditional THUMB2 wide branch from the given address to the given address.
        """

        if from_addr < to_addr:
            s_bit = 0
            offset = to_addr - from_addr - THUMB2_INST_WIDTH
        else:
            s_bit = 1
            offset = 2**25 - (from_addr + THUMB2_INST_WIDTH - to_addr)

        i1 = (offset >> 24) & 1
        i2 = (offset >> 23) & 1
        j1 = (0 if i1 else 1) ^ s_bit
        j2 = (0 if i2 else 1) ^ s_bit

        b2 = 0b11110000 | (s_bit << 2) | ((offset >> 20) & 0b11)
        b1 = (offset >> 12) & 0xff
        b4 = 0b10010000 | (j1 << 5) | (j2 << 3) | ((offset >> 9) & 0b111)
        b3 = (offset >> 1) & 0xff
        return chr(b1) + chr(b2) + chr(b3) + chr(b4)
