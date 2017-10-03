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

import socket, struct
from defs import *
from symbols import *

#The mask used to prevent values in the buffers from appearing like infoleaks
#when analysing the memory-mapped IO-Space. This isn't strictly necessary, but
#it makes the analysis easier.
OBF_MASK = 0xFFFFFFFFFFFFFFFF

#The size of the read chunk when reading large chunks of memory
READ_CHUNK_SIZE = 0x1000

#The offset of the PID in the proc entry
PROC_PID_OFFSET = 16

#The offset of the next field in the proc entry
PROC_NEXT_ENTRY_OFFSET = 168

#The offset of the next field in the task entry
TASK_NEXT_ENTRY_OFFSET = 40

def qword_at(buf, idx):
    """
    Reads the QWORD at the given index in the block of data provided
    """

    return struct.unpack("<Q", buf[(idx*QWORD_SIZE):((idx+1)*QWORD_SIZE)])[0]

class MemClient(object):
    """
    The client used to interact with the server stub
    """

    def __init__(self, server_ip, server_port):
        """
        Creates a new MemShell client to the given server address.
        """

        self.server_ip = server_ip
        self.server_port = server_port

        #Connecting to the server and getting the slide value
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_ip, self.server_port))
        self.kaslr_slide = struct.unpack("<Q", self.sock.recv(QWORD_SIZE))[0]

        #Reading the physical and virtual base addresses
        self.g_phys_base = self.read64(G_PHYS_BASE + self.slide());
        self.g_virt_base = self.read64(G_VIRT_BASE + self.slide());

    def slide(self):
        """
        Returns the KASLR slide value.
        """

        return self.kaslr_slide

    def read(self, addr, size):
        """
        Reads a chunk of memory in the kernel's VAS from the client
        """

        self.sock.send("c" + struct.pack("<QQ", addr ^ OBF_MASK, size ^ OBF_MASK)) 

        #Reading all the chunks
        bytes_left = size
        buf = ""
        while bytes_left > 0:
            chunk = self.sock.recv(min(READ_CHUNK_SIZE, bytes_left))
            buf += chunk
            bytes_left -= len(chunk)

        #Deobfuscating the block
        buf = ''.join(map(lambda x: chr(ord(x) ^ 0xFF), buf) )

        return buf

    def read128(self, addr):
        """
        Reads the 128-bit value at the given address.
        Returns a tuple of (high-64bits, low-64bits)
        """

        self.sock.send("r" + struct.pack("<Q", addr ^ OBF_MASK))
        vals = struct.unpack("<QQ", self.sock.recv(2 * QWORD_SIZE))
        return map(lambda x: x ^ OBF_MASK, vals)
    
    def read64(self, addr):
        """
        Reads the 64-bit value at the given address.
        """
        if addr % QWORD_SIZE != 0:
            raise Exception("Address must be QWORD-aligned : 0x%016X" % addr)
        dqword_aligned_addr = addr - (addr % (2 * QWORD_SIZE))
        tokens = self.read128(dqword_aligned_addr)
        return tokens[0] if addr % (2 * QWORD_SIZE) == 0 else tokens[1]

    def read32(self, addr):
        """
        Reads the 32-bit value at the given address.
        NOTE: This uses the underlying read primitive, so it:
                 (a) won't cause a 32-bit load operation
                 (b) might also read before/after the given address
              For these reasons this method is incompatible with certain operations,
              such as interacting with a device's hardware registers. If you need to
              perform such an operation, use "read32_strict" instead.
        """

        if addr % DWORD_SIZE != 0:
            raise Exception("Address must be DWORD-aligned : 0x%016X" % addr)
        qword_aligned_addr = addr - (addr % QWORD_SIZE)
        tokens = struct.unpack("<II", struct.pack("<Q", self.read64(qword_aligned_addr)))
        return tokens[0] if addr % QWORD_SIZE == 0 else tokens[1]

    def write64(self, addr, val):
        """
        Writes the given 64-bit value to the given address.
        """

        self.sock.send("w" + struct.pack("<QQ", addr ^ OBF_MASK, val ^ OBF_MASK))
        res = struct.unpack("<Q", self.sock.recv(QWORD_SIZE))[0]
        return res

    def write32(self, addr, val):
        """
        Writes the given 32-bit value to the given address.
        NOTE: This uses the underlying read primitive -- see read32 for more
              information. If you require a 32-bit store, use "write32_strict".
        """

        if addr % QWORD_SIZE == 0:
            next_dword = self.read32(addr + DWORD_SIZE)
            self.write64(addr, struct.unpack("<Q", struct.pack("<II", val, next_dword))[0])
        else:
            prev_dword = self.read32(addr - DWORD_SIZE)
            self.write64(addr - DWORD_SIZE, struct.unpack("<Q", struct.pack("<II", prev_dword, val))[0])

    def write32_strict(self, addr, val):
        """
        Performs a strict 32-bit store operation.
        """

        gadget = WRITE_32BIT_GADGET + self.slide()
        self.exec2(gadget, val, addr)

    def read32_strict(self, addr):
        """
        Performs a strict 32-bit load operation.
        """

        gadget = READ_32BIT_GADGET + self.slide()
        junk_addr = JUNK_ADDRESS + self.slide()
        self.exec2(gadget, addr - 0xA4, junk_addr - 0x4) #These offsets correspond to the 32-bit read gadget
        return self.read32(junk_addr)

    def race(self, addr, val):
        """
        Modifies the given value for a very short period of time, and then switches it back again
        """

        self.sock.send("f" + struct.pack("<QQ", addr ^ OBF_MASK, val ^ OBF_MASK))
        res = struct.unpack("<Q", self.sock.recv(QWORD_SIZE))[0]
        return res

    def exec2(self, func, arg1, arg2):
        """
        Executes the given function with the two given arguments.
        Does not return the return value of the function.
        """

        self.sock.send("x" + struct.pack("<QQQ", func ^ OBF_MASK,
                                                 arg1 ^ OBF_MASK,
                                                 arg2 ^ OBF_MASK))
        res = struct.unpack("<Q", self.sock.recv(QWORD_SIZE))[0]
        return res

    def exec_and_return(self, func):
        """
        Executes the given function with no arguments and returns
        the return value.
        """

        obj_addr = JUNK_ADDRESS + self.slide()                      #The address of the fake object we're crafting
        exec_func_gadget = EXEC_FUNCTION_GADGET + self.slide()      #The gadget that'll execute and store our func
        self.write64(obj_addr + 88, obj_addr + 96)                  #deref #1
        self.write64(obj_addr + 96, obj_addr + 108)                 #deref #2 (vtable)
        self.write64(obj_addr + 108 + 312, func)                    #func #1
        self.write64(obj_addr + 108 + 320, RET_ZERO + self.slide()) #func #2
        self.exec2(exec_func_gadget, obj_addr, obj_addr + 24)
        return self.read64(obj_addr + 24)                           #reading back the result

    def phys_to_virt(self, phys):
        """
        Returns the kernel virtual address corresponding to the physical address.
        """

        return phys - self.g_phys_base + self.g_virt_base

    def virt_to_phys(self, virt):
        """
        Returns the kernel physical address corresponding to the virtual address.
        """

        return virt - self.g_virt_base + self.g_phys_base

    def proc_for_pid(self, pid):
        """
        Returns the proc_t for the given pid or None if no such process exists
        """

        pidhashtbl = self.read64(PIDHASHTBL + self.slide())
        pidhash = self.read64(PIDHASH + self.slide())   
        entry = self.read64(pidhashtbl + QWORD_SIZE * (pidhash & pid))
        while entry != 0:
            proc_pid = self.read32(entry + PROC_PID_OFFSET)
            if proc_pid == pid:
                return entry
            entry = self.read64(entry + PROC_NEXT_ENTRY_OFFSET)
        return None

    def get_all_processes(self):
        """
        Returns a list of the proc_t instances
        """

        kern_proc = self.read64(KERNPROC + self.slide()) 
        procs = []
        proc = kern_proc
        while proc != 0:
            procs.append(proc)
            proc = self.read64(proc + QWORD_SIZE)
        return procs

    def get_kernel_task(self):
        """
        Returns the kernel task
        """

        return self.read64(KERNEL_TASK + self.slide())

    def get_all_tasks(self):
        """
        Returns a list of all the current task_t instances
        """

        kernel_task = self.get_kernel_task()
        tasks = []
        task = kernel_task
        while task != 0:
            tasks.append(task)
            task = self.read64(task + TASK_NEXT_ENTRY_OFFSET)
        return tasks
