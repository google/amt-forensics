#!/usr/bin/python
#
# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ctypes
import os
import struct
import uuid

libc = ctypes.cdll.LoadLibrary('libc.so.6')
ioctl = libc.ioctl
ioctl.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_char_p)
ioctl.restype = ctypes.c_int

IOCTL_MEI_CONNECT_CLIENT = 0xc0104801 # _IOWR('H' , 0x01, struct mei_connect_client_data)

amt = "12f80028-b4b7-4b2d-aca8-46e0ff65814c"

fd = os.open("/dev/mei", os.O_RDWR)
u = uuid.UUID(amt)
b = ctypes.c_buffer(u.get_bytes_le())
if ioctl(fd, IOCTL_MEI_CONNECT_CLIENT, b) == -1 :
  raise Error("ioctl error")
maxlen,vers = struct.unpack("<IB", b.raw[:5])

# print maxlen
# print vers

AMT_MAJOR_VERSION = 1
AMT_MINOR_VERSION = 1

GET_LOCAL_SYSTEM_ACCOUNT_REQUEST = 0x04000067;

cmd = struct.pack(
    "<BBHII", AMT_MAJOR_VERSION, AMT_MINOR_VERSION, 0, GET_LOCAL_SYSTEM_ACCOUNT_REQUEST, 40)
os.write(fd, cmd)
buf = os.read(fd, maxlen)

major_num, minor_num, reserved, command, length, status, username, password = struct.unpack(
    "<BBHIII33s33s", buf[:82])

# print major_num
# print minor_num
# print reserved
# print command
# print length
# print status
# print username
print password

os.close(fd)
