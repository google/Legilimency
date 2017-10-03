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

from defs import *
import struct

#The offset of the "rxd" field in the dma_info structure
RXD_OFFSET = 64

#The offset of the "nrxd" field in the dma_info structure
NRXD_OFFSET = 108

#The size of a 64-bit RX descriptor in the DMA descriptor chain
RX_DESC_SIZE = 16

#The offset of the rings_info_ptr field in the PCIe shared structure
RINGS_INFO_PTR_OFFSET = 12 * DWORD_SIZE

#The offset of the flow ring instance array in the PCIe object
FLOW_RINGS_OFFSET = 1328

#The size of a ring_mem entry in the ringmem array
RING_MEM_ENTRY_SIZE = 16

#The number of D2H/H2D rings (not including flow rings!)
NUM_RINGS = 5

#The number of D2H rings (not including flow rings!)
NUM_D2H_RINGS = 3

#The indices of each of the generic H2D/D2H rings (not including flow rings)
H2D_MSGRING_CONTROL_SUBMIT   = 0
H2D_MSGRING_RXPOST_SUBMIT    = 1
D2H_MSGRING_CONTROL_COMPLETE = 2
D2H_MSGRING_TX_COMPLETE      = 3
D2H_MSGRING_RX_COMPLETE      = 4

#The offsets of the AppleBCMWLANPCIeSubmissionRing instances for each H2D ring in the PCIe object
H2D_RING_OFFSETS = {H2D_MSGRING_CONTROL_SUBMIT : 1232,
                    H2D_MSGRING_RXPOST_SUBMIT  : 1272}

#The offsets of the AppleBCMWLANPCIeCompletionRing instances for each D2H ring in the PCIe object
D2H_RING_OFFSETS = {D2H_MSGRING_CONTROL_COMPLETE : 1240,
                    D2H_MSGRING_TX_COMPLETE      : 1288,
                    D2H_MSGRING_RX_COMPLETE      : 1280}

#The types of indices present
H2D_WRITE = 0
H2D_READ  = 1
D2H_WRITE = 2
D2H_READ  = 3

#The hostaddr offsets for each type of index provided, within rings_info structure
INDEX_HOSTADDR_OFFSETS = {H2D_WRITE : 5  * DWORD_SIZE,
                          H2D_READ  : 7  * DWORD_SIZE,
                          D2H_WRITE : 9  * DWORD_SIZE,
                          D2H_READ  : 11 * DWORD_SIZE}


class BCMHostDongleInterface(object):
    """
    This class allows inspection of the H2D/D2H communication between the BCM chip and the host.
    """

    def __init__(self, bcmclient):
        """
        Creates a new instance, using the underlying BCMClient to communicate with the Wi-Fi SoC.
        """

        self.bcmclient = bcmclient
        self.client = bcmclient.client
    def dump_rx_descriptors(self, dma_object_addr):
        """
        Dumps each RXD in the given DMA object. 
        """

        rxd = self.bcmclient.fw_read32(dma_object_addr + RXD_OFFSET)
        nrxd = struct.unpack("<HH", struct.pack("<I", self.bcmclient.fw_read32(dma_object_addr + NRXD_OFFSET)))[0]
        print "rxd: %X" % rxd
        print "nrxd: %X" % nrxd
        for i in range(0, nrxd):
            print "desc[%d] : 0x%016X" % (i, self.bcmclient.fw_read64(rxd + RX_DESC_SIZE*i + QWORD_SIZE))

    def get_pciedev_shared_t_addr(self):
        """
        Returns the address of the pciedev_shared_t structure.
        """

        return self.bcmclient.fw_read32(self.bcmclient.ram_offset + self.bcmclient.ram_size - DWORD_SIZE)

    def dump_pcie_rings(self):
        """
        Dumps the information about each of the PCIe rings.
        """

        pciedev_shared_t_addr = self.bcmclient.fw_read32(self.bcmclient.ram_offset + self.bcmclient.ram_size - DWORD_SIZE)
        rings_info_ptr = self.bcmclient.fw_read32(pciedev_shared_t_addr + RINGS_INFO_PTR_OFFSET)
        ringmem_ptr = self.bcmclient.fw_read32(rings_info_ptr)
        print "rings_info_ptr: %X" % rings_info_ptr
        print "pciedev_shared_t_addr: 0x%08X" % pciedev_shared_t_addr
        print "ringmem_ptr: %X" % ringmem_ptr

        for i in range(0, NUM_RINGS):
            ring_mem_entry = self.bcmclient.fw_read(ringmem_ptr + i * RING_MEM_ENTRY_SIZE)
            (_, _, _, max_items, len_items, ringaddr) = struct.unpack("<HBBHHQ", ring_mem_entry)
            ringaddr_ptr = ringmem_ptr + (i + 1) * RING_MEM_ENTRY_SIZE - QWORD_SIZE
            ringaddr = self.bcmclient.fw_read64(ringaddr_ptr)
            print "ring : %d" % i
            print "max_items: %d, len_items: %d" % (max_items, len_items)
            print "ringaddr_ptr: %X, ringaddr: %X " % (ringaddr_ptr, ringaddr)

    def get_index_hostaddr(self, index_type):
        """
        Returns the hostaddr (IO-Space address) of the index type provided
        """
       
        pciedev_shared_t_addr = self.bcmclient.fw_read32(self.bcmclient.ram_offset + self.bcmclient.ram_size - DWORD_SIZE)
        rings_info_ptr = self.bcmclient.fw_read32(pciedev_shared_t_addr + RINGS_INFO_PTR_OFFSET)
        return self.bcmclient.fw_read32(rings_info_ptr + INDEX_HOSTADDR_OFFSETS[index_type])

    def get_h2d_w_idx_hostaddr(self):
        """
        Returns the address of the h2d_w_idx_hostaddr field in the rings_info_ptr
        """
        
        return self.get_index_hostaddr(H2D_WRITE)

    def get_h2d_r_idx_hostaddr(self):
        """
        Returns the address of the h2d_r_idx_hostaddr field in the rings_info_ptr
        """
        
        return self.get_index_hostaddr(H2D_READ)

    def get_d2h_w_idx_hostaddr(self):
        """
        Returns the address of the d2h_w_idx_hostaddr field in the rings_info_ptr
        """

        return self.get_index_hostaddr(D2H_WRITE)

    def get_d2h_r_idx_hostaddr(self):
        """
        Returns the address of the d2h_r_idx_hostaddr field in the rings_info_ptr
        """

        return self.get_index_hostaddr(D2H_READ)

    def get_ring_instance(ring_index):
        """
        Returns the ring instance for the corresponding ring index
        """
        pcie_obj = self.bcmclient.get_pcie_obj()
        
        if ring_index in H2D_RING_OFFSETS:
            clazz = AppleBCMWLANPCIeSubmissionRing
            off = H2D_RING_OFFSETS[ring_index]
        
        elif ring_index in D2H_RING_OFFSETS:
            clazz = AppleBCMWLANPCIeCompletionRing
            off = D2H_RING_OFFSETS[ring_index]
        
        else:
            raise Exception("Invalid ring index: %d" % ring_index)
        
        return clazz(self.client, self.client.read(pcie_obj + off), ring_index)

    def get_h2d_msgring_control_submit_ring(self):
        """
        Returns the AppleBCMWLANPCIeSubmissionRing instance for ring #0 (H2D_MSGRING_CONTROL_SUBMIT)
        """

        return self.get_ring_instance(H2D_MSGRING_CONTROL_SUBMIT)

    def get_h2d_msgring_rxpost_submit_ring(self):
        """
        Returns the AppleBCMWLANPCIeSubmissionRing instance for ring #1 (H2D_MSGRING_RXPOST_SUBMIT)
        """
        
        return self.get_ring_instance(H2D_MSGRING_RXPOST_SUBMIT)

    def get_d2h_msgring_control_complete_ring(self):
        """
        Returns the AppleBCMWLANPCIeCompletionRing instance for ring #2 (D2H_MSGRING_CONTROL_COMPLETE)
        """

        return self.get_ring_instance(D2H_MSGRING_CONTROL_SUBMIT)

    def get_d2h_msgring_tx_complete_ring(self):
        """
        Returns the AppleBCMWLANPCIeCompletionRing instance for ring #3 (D2H_MSGRING_TX_COMPLETE)
        """
        
        return self.get_ring_instance(D2H_MSGRING_TX_COMPLETE)

    def get_d2h_msgring_rx_complete_ring(self):
        """
        Returns the AppleBCMWLANPCIeCompletionRing instance for ring #4 (D2H_MSGRING_RX_COMPLETE)
        """
        
        return self.get_ring_instance(D2H_MSGRING_RX_COMPLETE)

    def get_flow_ring(self, flow_id):
        """
        Returns the flow ring corresponding to the given flow ID
        """

        pcie_obj = self.bcmclient.get_pcie_obj()
        obj_addr = self.client.read64(pcie_obj + flow_id * QWORD_SIZE + FLOW_RINGS_OFFSET)
        if obj_addr == 0:
            return None
        return AppleBCMWLANPCIeSubmissionRing(self.client, obj_addr, flow_id + NUM_D2H_RINGS)

    def dump_submission_and_completion_rings(self):
       """
       Dumps information about the submission and completion rings
       """

       compl_rings = [self.get_d2h_msgring_control_complete_ring(),
                      self.get_d2h_msgring_tx_complete_ring(),
                      self.get_d2h_msgring_rx_complete_ring()]

       subm_rings = [self.get_h2d_msgring_control_submit_ring(),
                     self.get_h2d_msgring_rxpost_submit_ring()]

       for ring in (subm_rings + compl_rings):
           print "Ring ID:           %d"    % ring.get_ring_id()
           print "Ring Base Address: %016X" % ring.get_base_address()
           print "Ring Element Size: %d"    % ring.get_element_size()
           print "Ring Index Pointer %016X" % ring.get_index_pointer()

    
