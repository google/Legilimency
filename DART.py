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
import struct
from defs import *
from symbols import *

#The base address of the IO-Space mapping governed by DART
DART_IO_SPACE_BASE = 0x80000000

#The memory range translated by a first-level DART entry
DART_FIRST_LEVEL_ENTRY_SIZE= 0x200000

#the size of the mapping governed by a second-level DART entry
DART_SECOND_LEVEL_ENTRY_SIZE = 0x1000

#The size of the first-level DART table
DART_FIRST_LEVEL_TABLE_SIZE = 0x1000

#The size of the second-level DART table
DART_SECOND_LEVEL_TABLE_SIZE = 0x1000

#The mask used to retrieve a second-level entry's address
SECOND_LEVEL_ENTRY_MASK = 0xFFFFFFFFFFFFF000

#The mask used to get a translation's MSBs
TRANSLATION_OFFSET_MASK = 0xFFF

#The offset of the DART table within the DART instance
DART_TABLE_OFFSET = 312

#The offset of the DART registers within the DART instance
DART_REGISTERS_OFFSET = 384

#The offset of the L0 descriptor in the DART registers
L0_DESC_REG_OFFSET = 64

class DART(object):
    """
    A class representing the DART IO-Space -> PA resolution table.
    """

    def __init__(self, client, sl_dart, verbose=True):
        self.sl_dart = sl_dart
        self.client = client 
        self.io_to_pa_map = {}
        self.pa_to_io_map = {}

        #Reading the DART table and HW-register pointers
        self.dart_table = self.client.read64(self.sl_dart + DART_TABLE_OFFSET)
        self.dart_registers = self.client.read64(self.sl_dart + DART_REGISTERS_OFFSET)

        #Going over each of the table's first-level entries
        self.l0_ptr = self.client.read64(self.dart_table)
        self.l1_ptr = self.client.read64(self.l0_ptr + QWORD_SIZE)
        self.dart_l2_addrs = []
        l1_pa_table = self.client.read(self.l1_ptr, DART_FIRST_LEVEL_TABLE_SIZE)
        if verbose:
            print "l0_ptr: %016X" % self.l0_ptr
            print "l1_ptr: %016X" % self.l1_ptr
        for l1_idx in range(0, DART_FIRST_LEVEL_TABLE_SIZE, QWORD_SIZE):

            #Skipping unpopulated first-level entries
            l1_pa = qword_at(l1_pa_table, l1_idx/QWORD_SIZE)
            if l1_pa == 0:
                continue #Not populated

            #Finding the second-level descriptor bytes
            l1_va = self.client.read64(self.l0_ptr + 2*QWORD_SIZE + l1_idx)
            l2_ptr = self.client.read64(l1_va + QWORD_SIZE)
            self.dart_l2_addrs.append(l2_ptr)
            l2_pa_table = self.client.read(l2_ptr, DART_SECOND_LEVEL_TABLE_SIZE)
            if verbose:
                print "L1 VA: %016X" % l1_va
                print "l2_ptr: %016X" % l2_ptr
            for l2_idx in range(0, DART_SECOND_LEVEL_TABLE_SIZE, QWORD_SIZE):

                #Skipping unpopulated second-level entries
                l2_entry = qword_at(l2_pa_table, l2_idx/QWORD_SIZE)
                if l2_entry == 0:
                    continue

                #Adding the IO-Space -> PA mapping
                io_space_addr = DART_IO_SPACE_BASE + \
                                ((l1_idx/QWORD_SIZE) * DART_FIRST_LEVEL_ENTRY_SIZE) + \
                                ((l2_idx/QWORD_SIZE) * DART_SECOND_LEVEL_ENTRY_SIZE)
                if verbose:
                    print "0x%08X -> 0x%016X" % (io_space_addr, l2_entry)
                self.io_to_pa_map[io_space_addr] = l2_entry & SECOND_LEVEL_ENTRY_MASK

        #Inverting the mapping to keep an IO-Space -> PA mapping
        for k, v in self.io_to_pa_map.iteritems():
            self.pa_to_io_map[v] = self.io_to_pa_map.get(v, [])
            if type(self.pa_to_io_map[v]) != list:
                self.pa_to_io_map[v] = [self.pa_to_io_map[v]]
            self.pa_to_io_map[v].append(k)

    def io_to_pa(self, io_space_addr):
        """
        Translates the given IO-Space address to the corresponding physical address
        """

        aligned_io_space_addr = io_space_addr & SECOND_LEVEL_ENTRY_MASK
        offset = io_space_addr & TRANSLATION_OFFSET_MASK
        if aligned_io_space_addr in self.io_to_pa_map:
            return self.io_to_pa_map[aligned_io_space_addr] + offset
        return None

    def pa_to_io(self, pa_addr):
        """
        Translates the given IO-Space address to the corresponding physical address
        """

        aligned_pa_addr = pa_addr & SECOND_LEVEL_ENTRY_MASK
        offset = pa_addr & TRANSLATION_OFFSET_MASK
        if aligned_pa_addr in self.pa_to_io_map:
            return self.pa_to_io_map[aligned_pa_addr][0] + offset
        return None

    def map_io_space(self, io_addr, pa_addr):
        """
        Maps the given IO-Space address to the given physical address.
        """

        #Calculating the first and second level indices
        l1_idx = (io_addr - DART_IO_SPACE_BASE) / DART_FIRST_LEVEL_ENTRY_SIZE
        l2_idx = ((io_addr - DART_IO_SPACE_BASE) - (l1_idx * DART_FIRST_LEVEL_ENTRY_SIZE)) / DART_SECOND_LEVEL_ENTRY_SIZE

        #Is there a second level descriptor at this address?
        l1_va = self.client.read64(self.l0_ptr + 2*QWORD_SIZE + l1_idx*QWORD_SIZE)
        l2_ptr = self.client.read64(l1_va + QWORD_SIZE)
        if l2_ptr == 0:
            raise Exception("No second level entry descriptor at index %d" % l1_idx)

        #Writing the translation
        self.client.write64(l2_ptr + l2_idx*QWORD_SIZE, pa_addr | 0b11)

    def get_io_addrs(self):
        """
        Returns a list of IO base addresses mapped to IO-Space
        """

        return sorted(self.io_to_pa_map.keys())

    def read_reg(self, offset):
        """
        Reads the hardware register at the given offset
        NOTE: The hardware *requires* a strict 32-bit load, anything else returns 0xFF's.
        """

        return self.client.read32_strict(self.dart_registers + offset)

    def write_reg(self, offset, val):
        """
        Writes the hardware register at the given offset.
        NOTE: The hardware *requires* a strict 32-bit store.
        """

        self.client_write32_strict(self.dart_registers + offset, val)

    def get_l0_desc(self):
        """
        Returns the L0 descriptor from DART's HW registers.
        """

        return self.read_reg(L0_DESC_REG_OFFSET)

    def get_l0_pa(self):
        """
        Extracts the host physical address of the L0 table from the L0 descriptor in DART's registers.
        """

        return (self.get_l0_desc & 0xFFFFFF) << 12

    def map_l0_table(self, l0_table_pa):
        """
        Maps the given L0 table into DART's L0 descriptor.
        NOTE: DART caches *many* of the IO-Space mappings, therefore changes
              might take time to become apparent. 
        """

        self.write_reg(L0_DESC_REG_OFFSET, ((l0_table_pa >> 12) & 0xFFFFFF) | 0x80000000)
