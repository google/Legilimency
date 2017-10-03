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

import struct
from bisect import bisect
from MemClient import MemClient
from defs import *
from symbols import *


#The offsets of fields within zone_page_metadata (see zalloc.c)
OFF_OFFSET  = 16
META_OFFSET = 20
ZONE_PAGE_METADATA_SIZE = 24

#The offsets of the fields within zone_t (see zalloc.h)
INTERMEDIATE_QUEUE_OFFSET = 40
ALL_USED_QUEUE_OFFSET     = 56

#The kalloc zone sizes
KALLOC_ZONE_SIZES = [0x10,
                     0x20,
                     0x30,
                     0x40,
                     0x50,
                     0x60,
                     0x80,
                     0xA0,
                     0xC0,
                     0x100,
                     0x120,
                     0x200,
                     0x240,
                     0x400,
                     0x480,
                     0x500,
                     0x800,
                     0x1000,
                     0x2000,
                     0x4000,
                     0x8000]

def create_zone_queue_allocation_generator(client, zone_queue, zone_alloc_size):
    """
    Creates a generator over the allocations in the given zone queue.
    This can be used to iterate over each allocation in the zone.
    """

    #Finding the zone-related bounds
    zone_map_min = client.read64(ZONE_MAP_MIN_ADDRESS + client.slide())
    zone_meta_min = client.read64(ZONE_METADATA_REGION_MIN + client.slide())
    print "zone_map_min: %016X" % zone_map_min
    print "zone_meta_min: %016X" % zone_meta_min

    #Going over each metadata entry 
    curr = zone_queue
    while True:

        #Printing some information about the current node
        off = client.read32(curr + OFF_OFFSET)
        meta = client.read32(curr + META_OFFSET)
        free_count, zindex, page_count = struct.unpack("<HBB", struct.pack("<I", meta))
        print "current: %016X" % curr
        print "offset: 0x%X" % off
        print "free_count: 0x%X" % free_count
        print "zindex: 0x%X" % zindex
        print "page_count: 0x%X" % page_count

        #Making sure the metadata is within the allowed ranges
        if not curr >= zone_meta_min:
            print "metadata 0x%016X not within zone_meta ranges!" % curr

        #Going over each page associated with zone in the zone_map
        #and emitting each allocation block in our generator
        meta_idx = (curr - zone_meta_min) / ZONE_PAGE_METADATA_SIZE
        print "meta_idx: %d" % meta_idx
        start_addr = zone_map_min + meta_idx * PAGE_SIZE
        end_addr = start_addr + page_count * PAGE_SIZE
        for addr in range(start_addr, end_addr, zone_alloc_size):
            yield addr

        #Going to the next node in the queue
        curr = client.read64(curr)
        if curr == zone_queue:
            break #Looped back to the start - let's stop

def find_object_by_vtable(client, vtable, allocation_size=None, find_all=False):
    """
    Find an object with the given vtable in the kalloc zones. If the allocation size
    is specified, only the relevant kalloc zone is queried. If find_all is specified,
    a list of all instances of such objects are returned.

    If no matching instances are found, None is returned.
    """
    
    #Do we have the allocation size?
    zones = []
    if allocation_size:
        zone_idx = bisect(KALLOC_ZONE_SIZES, allocation_size)
        zones.append((client.read64(K_ZONE + client.slide() + zone_idx*QWORD_SIZE), KALLOC_ZONE_SIZES[zone_idx]))
    else:
        for zone_idx in range(0, len(KALLOC_ZONE_SIZES)):
            zones.append((client.read64(K_ZONE + client.slide() + zone_idx*QWORD_SIZE), KALLOC_ZONE_SIZES[zone_idx]))

    #For each zone, create a generator over the zone
    results = []
    for (zone, zone_allocation_size) in zones:

        #Gathering the relevant queues
        all_used_queue = zone + ALL_USED_QUEUE_OFFSET
        intermediate_queue = zone + INTERMEDIATE_QUEUE_OFFSET
        queues = [all_used_queue, intermediate_queue]
   
        #Going over each of the pages in the zone, either used or intermediate
        for queue in queues:
            for allocation in create_zone_queue_allocation_generator(client, queue, zone_allocation_size):
                if client.read64(allocation) == vtable:
                    if not find_all:
                        return allocation
                    else:
                        results.append(allocation)

    #Return the results
    return results if len(results) > 0 else None
