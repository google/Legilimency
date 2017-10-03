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
import struct

#The number of translation table entries per level
NUM_ENTRIES_PER_LEVEL = [2, 2048, 2048]

#The span of each translation table entry per level
ENTRY_SPAN_PER_LEVEL = [1<<36, 1<<25, 1<<14]

#Translation between APTable values to the string respresenting their content
AP_TABLE_TO_STRING = ["No effect on permission lookup",
                      "EL0: No access, EL1: No effect",
                      "EL0: No access, EL1: No access",
                      "EL0: No access, EL1: no write "]

#The virtual base address of the kernel (TTBR1)
KERNEL_VIRT_BASE = 0xFFFFFFE000000000

#The offset of the map field in the task_t structure
MAP_OFFSET = 32

#The offset of the pmap field in the map structure
PMAP_OFFSET = 72

#The mask used to retrieve the descriptor type
DESC_TYPE_MASK = 0b11

#The types of descriptors
L3_PAGE_DESC_TYPE = 0b11
TABLE_DESC_TYPE   = 0b11
BLOCK_DESC_TYPE   = 0b01

#L3 Page descriptor shifts and masks
L3_PAGE_DESC_AP_SHIFT  = 6
L3_PAGE_DESC_AP_MASK   = 0b11

L3_PAGE_DESC_PA_SHIFT  = 0
L3_PAGE_DESC_PA_MASK   = 0xFFFFFFFFC000

L3_PAGE_DESC_UXN_SHIFT = 54
L3_PAGE_DESC_UXN_MASK  = 0b1

L3_PAGE_DESC_PXN_SHIFT = 53
L3_PAGE_DESC_PXN_MASK  = 0b1

#Block descriptor shifts and masks
BLOCK_DESC_AP_SHIFT  = 6
BLOCK_DESC_AP_MASK   = 0b11

BLOCK_DESC_PA_SHIFT  = 0
BLOCK_DESC_PA_MASK   = 0xFFFFFE000000

BLOCK_DESC_UXN_SHIFT = 54
BLOCK_DESC_UXN_MASK  = 0b1

BLOCK_DESC_PXN_SHIFT = 53
BLOCK_DESC_PXN_MASK  = 0b1

#Table descriptor shifts and masks
TABLE_DESC_APTABLE_SHIFT  = 61
TABLE_DESC_APTABLE_MASK   = 0b11

TABLE_DESC_PA_SHIFT       = 0
TABLE_DESC_PA_MASK        = 0xFFFFFFFFC000

TABLE_DESC_UXNTABLE_SHIFT = 60
TABLE_DESC_UXNTABLE_MASK  = 0b1

TABLE_DESC_PXNTABLE_SHIFT = 59
TABLE_DESC_PXNTABLE_MASK  = 0b1

TABLE_DESC_NSTABLE_SHIFT  = 63
TABLE_DESC_NSTABLE_MASK   = 0b1

#L3 descriptor offset and mask table
L3_PAGE_DESC_OFFSETS = {'ap'  : (L3_PAGE_DESC_AP_SHIFT,  L3_PAGE_DESC_AP_MASK),
                       'pa'  : (L3_PAGE_DESC_PA_SHIFT,  L3_PAGE_DESC_PA_MASK),
                       'uxn' : (L3_PAGE_DESC_UXN_SHIFT, L3_PAGE_DESC_UXN_MASK),
                       'pxn' : (L3_PAGE_DESC_PXN_SHIFT, L3_PAGE_DESC_PXN_MASK)}

#Block descriptor offset and mask table
BLOCK_DESC_OFFSETS = {'ap'  : (BLOCK_DESC_AP_SHIFT,  BLOCK_DESC_AP_MASK),
                      'pa'  : (BLOCK_DESC_PA_SHIFT,  BLOCK_DESC_PA_MASK),
                      'uxn' : (BLOCK_DESC_UXN_SHIFT, BLOCK_DESC_UXN_MASK),
                      'pxn' : (BLOCK_DESC_PXN_SHIFT, BLOCK_DESC_PXN_MASK)}

#Table descriptor offset and mask table
TABLE_DESC_OFFSETS = {'aptable'  : (TABLE_DESC_APTABLE_SHIFT,  TABLE_DESC_APTABLE_MASK),
                      'pa'       : (TABLE_DESC_PA_SHIFT,       TABLE_DESC_PA_MASK),
                      'uxntable' : (TABLE_DESC_UXNTABLE_SHIFT, TABLE_DESC_UXNTABLE_MASK),
                      'pxntable' : (TABLE_DESC_PXNTABLE_SHIFT, TABLE_DESC_PXNTABLE_MASK),
                      'nstable'  : (TABLE_DESC_NSTABLE_SHIFT,  TABLE_DESC_NSTABLE_MASK)}

class TranslationTable(object):
    """
    An ARMv8 translation table, as the one used by the kernel to manage
    the VA->PA mappings in TTBR1.
    """

    def __init__(self, client, table_base, verbose=False):
        """
        Creates a new TranslationTable governing over the given table.
        """
        self.client = client
        self.table_base = table_base
        elf.translations = []
        self.verbose = verbose
        self.parse_translation_table(self.table_base, 1, KERNEL_VIRT_BASE)

    def is_desc_type(self, desc, desc_type):
        """
        Returns True iff the given descriptor is an L3 page descriptor
        """

        return (desc & DESC_TYPE_MASK) == desc_type

    def get_field(self, desc, shift, mask):
        """
        Returns the field in the given descriptor contained under the given shift and mask
        """

        return (desc >> shift) & mask

    def parse_translation_table(self, table_virt, level, va_base):
        """
        Parses the given level of the translation table. Adds any relevant mappings
        to the translation tables mapping.
        """

        #Fetching the parameters for this translation level
        entry_span = ENTRY_SPAN_PER_LEVEL[level - 1]
        num_entries = NUM_ENTRIES_PER_LEVEL[level - 1]

        #Reading all the descriptors in the table in advance - this is a little faster
        #than iteratively reading
        descs = []
        table_data = self.client.read(table_virt, num_entries * QWORD_SIZE)
        descs = [qword_at(table_data, i) for i in range(0, num_entries)]
 
        #Handling the case where there's an odd number of entries. I don't think
        #the VMSA supports this, but better safe than sorry
        if num_entries % 2 != 0:
            descs.append(self.client.read64(table_virt + num_entries - 1))

        #Dumping each descriptor in the table
        for i in range(0, num_entries):

            #Reading the descriptor and calculating its VA bounds
            desc = descs[i]
            va_start = va_base + i * entry_span
            va_end = va_start + entry_span - 1

            #Is this an L3 table?
            if level == 3:

                #Is this a page descriptor?
                if self.is_desc_type(desc, L3_PAGE_DESC_TYPE):
                    pa_start = self.get_field(desc, *L3_PAGE_DESC_OFFSETS['pa'])
                    pa_end = pa_start + entry_span - 1
                    ap_2_1 = self.get_field(desc, *L3_PAGE_DESC_OFFSETS['ap'])
                    uxn    = self.get_field(desc, *L3_PAGE_DESC_OFFSETS['uxn'])
                    pxn    = self.get_field(desc, *L3_PAGE_DESC_OFFSETS['pxn'])
                    if self.verbose:
                        print (level * " ") + "[%016X-%016X] -> [%016X-%016X]" % (va_start, va_end, pa_start, pa_end)
                        print (level * " ") + "<AP: %s, UXN: %d, PXN: %d>" % (bin(ap_2_1), uxn, pxn)
                    self.translations.append((va_start, va_end, pa_start, pa_end))

            else:
                #Is this a block descriptor?
                if self.is_desc_type(desc, BLOCK_DESC_TYPE):
                    pa_start = self.get_field(desc, *BLOCK_DESC_OFFSETS['pa'])
                    pa_end = pa_start + entry_span - 1
                    ap_2_1 = self.get_field(desc, *BLOCK_DESC_OFFSETS['ap'])
                    uxn    = self.get_field(desc, *BLOCK_DESC_OFFSETS['uxn'])
                    pxn    = self.get_field(desc, *BLOCK_DESC_OFFSETS['pxn'])
                    if self.verbose:
                        print (level * " ") + "[%016X-%016X] -> [%016X-%016X]" % (va_start, va_end, pa_start, pa_end)
                        print (level * " ") + "<AP: %s, UXN: %d, PXN: %d>" % (bin(ap_2_1), uxn, pxn)
                    self.translations.append((va_start, va_end, pa_start, pa_end))

                #Is this a table descriptor?
                elif self.is_desc_type(desc, TABLE_DESC_TYPE):
                    next_table_pa = self.get_field(desc, *TABLE_DESC_OFFSETS['pa'])
                    next_table_va = self.client.phys_to_virt(next_table_pa)
                    nstable  = self.get_field(desc, *TABLE_DESC_OFFSETS['nstable'])
                    aptable  = self.get_field(desc, *TABLE_DESC_OFFSETS['aptable'])
                    uxntable = self.get_field(desc, *TABLE_DESC_OFFSETS['uxntable'])
                    pxntable = self.get_field(desc, *TABLE_DESC_OFFSETS['pxntable'])
                    if self.verbose:
                        print (level * " ") + "[%016X-%016X] : Table descriptor (phys: %016X, virt: %016X)" % (va_start, va_end, next_table_pa, next_table_va)
                        print (level * " ") + "<NSTable: %d, APTable: %s, UXNTable: %d, PXNTable: %d>" % (nstable, bin(aptable), uxntable, pxntable)
                    self.parse_translation_table(next_table_va, level + 1, va_start)

    def va_to_pa(self, va):
        """
        Translates the given VA to a PA, if the mapping is present. Otherwise returns None.
        """
        for (va_start, va_end, pa_start, pa_end) in self.translations:
            if va_start <= va <= va_end:
                return pa_start + (va - va_start)
        return None

    def pa_to_va(self, pa, find_all=False):
        """
        Translates the given PA to a VA if a mapping exists. Otherwise returns None.
        If find_all is specified, returns a list of all matching VAs.
        """

        results = []
        for (va_start, va_end, pa_start, pa_end) in self.translations:
            if pa_start <= pa <= pa_end:
                va = va_start + (pa - pa_start)
                if not find_all:
                    return va
                results.append(va)

        return results if (not find_all or len(results) == 0) else None

    @classmethod
    def get_kernel_translation_table(cls, client):
        """
        Factory method that returns the kernel translation table
        """

        kernel_task = client.get_kernel_task()
        pmap = client.read64(client.read64(client.read64(kernel_task + MAP_OFFSET) + PMAP_OFFSET))
        return TranslationTable(client, pmap)
