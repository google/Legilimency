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

#iOS 10 uses 16KB pages
PAGE_SIZE = 0x4000

#Size of a DWORD
DWORD_SIZE = 4

#Size of a QWORD
QWORD_SIZE = 8

#The width, in bytes, of a THUMB2 instruction
THUMB2_INST_WIDTH = 4

#The number of copied preamble bytes from the hooked function's header
HOOK_PREAMBLE_BYTES = 6

#The default port used by the server
DEFAULT_PORT = 1337

#A 32-bit garbage value
GARBAGE_VALUE = 0xCCCCCCCC
