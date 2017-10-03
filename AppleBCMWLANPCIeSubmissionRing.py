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

from MemClient import MemClient
from defs import *
from symbols import *
from kalloc import *

#The offset of the base address field in the AppleBCMWLANPCIeSubmissionRing instance
BASE_ADDRESS_OFFSET = 248

#The offset of the element size field in the AppleBCMWLANPCIeSubmissionRing instance
ELEMENT_SIZE_OFFSET = 92

#The offset of the index pointer field in the AppleBCMWLANPCIeSubmissionRing instance
INDEX_POINTER_OFFSET = 184

#The offset of the read index pointer field in the AppleBCMWLANPCIeSubmissionRing instance
R_INDEX_POINTER_OFFSET = 176

#The offset of the max index field in the AppleBCMWLANPCIeSubmissionRing instance
MAX_INDEX_OFFSET = 88

class AppleBCMWLANPCIeSubmissionRing(object):
    """
    This class is used to represent an AppleBCMWLANPCIeSubmissionRing instance
    """

    def __init__(self, client, addr, ring_id):
        """
        Creates a new client, using the underlying MemShell client and the given instance address
        """

        self.client = client
        self.addr = addr
        self.ring_id = ring_id

    def get_base_address(self):
        """
        Returns the ring's base address in the kernel VAS
        """

        return self.client.read64(self.addr + BASE_ADDRESS_OFFSET) 
        
    def get_element_size(self):
        """
        Returns the ring's element size
        """

        return self.client.read32(self.addr + ELEMENT_SIZE_OFFSET) 
 
    def get_index_pointer(self):
        """
        Returns the pointer to the ring's index in the kernel VAS (which is also mapped to IO-Space!)
        """

        return self.client.read64(self.addr + INDEX_POINTER_OFFSET)

    def get_r_index_pointer(self):
        """
        Returns the pointer to the ring's read-index in the kernel VAS (which is also mapped to IO-Space!)
        """

        return self.client.read64(self.addr + R_INDEX_POINTER_OFFSET) 
 
    def get_max_index(self):
        """
        Returns the ring's maximal allowed index
        """

        return self.client.read32(self.addr + MAX_INDEX_OFFSET)

    def get_ring_id(self):
        """
        Returns the ring's ID
        """

        return self.ring_id 
