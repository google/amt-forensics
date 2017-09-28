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

import base64
import datetime
import struct
import enum
import pprint
import collections
import json

# All structs etc referenced from within Intel AMT SDK:
# /Windows/Intel_AMT/Samples/WS-Management/AccessMonitor/C++/AccessMonitorTypes.h


FILE_TO_DECODE = "./audit_log.log"
DEBUG = False


class InitiatorType(enum.Enum):
  HTTP_DIGEST = 0
  KERBEROS_SID = 1
  LOCAL_INITIATOR = 2


class AddressType(enum.Enum):
  IPV4_ADDR = 0
  IPV6_ADDR = 1
  NONE = 2


class AuditAppID(enum.Enum):
  SECURITY_ADMIN_APPID = 16  # "Security Admin"
  RCO_APPID = 17   # "RCO"
  REDIR_MANAGER_APPID = 18   # "Redirection Manager"
  FIRMWARE_UPDATE_MANAGER_APPID = 19  # "Firmware Update Manager"
  SECURITY_AUDIT_LOG_APPID = 20  # "Security Audit Log"
  NETWORK_TIME_APPID = 21   # "Network Time"
  NETWORK_ADMIN_APPID = 22   # "Network Administration"
  STORAGE_ADMIN_APPID = 23   # "Storage Administration"
  EVENT_MANAGER_APPID = 24   # "Event Manager"
  CB_MANAGER_APPID = 25   # "System Defense Manager"
  AGENT_PRESENCE_MANAGER_APPID = 26  # "Agent Presence Manager"
  WIRELESS_CONFIG_APPID = 27   # "Wireless Configuration"
  EAC_APPID = 28   # "EAC"
  KVM_APPID = 29   # "KVM"
  USER_OPT_IN_APPID = 30   # "User Opt-In"


EventID_list = [
    # Security
    "AMT Provisioning Started","AMT Provisioning Completed","ACL Entry Added",
    "ACL Entry Modified","ACL Entry Removed","ACL Access with invalid credentials",
    "ACL Entry Enabled","TLS State Changed","TLS Server Certificate Set",
    "TLS Server Certificate Remove","TLS Trusted Root Certificate Added",
    "TLS Trusted Root Certificate Removed","TLS Pre-shared Key Set",
    "Kerberos Settings Modified","Kerberos Master Key Modified",
    "Flash Wear-Out Counters Reset","Power Package Modified",
    "Set realm Authentication mode","Upgrade from client to admin control mode",
    # RCO
    "Performed Power-Up","Performed Power-Down","Performed Power-Cycle",
    "Performed Reset","Set Boot Options",
    # REDIR
    "IDE-R Session Opened","IDE-R Session Closed ","IDE-R Enabled",
    "IDE-R Disabled","SoL Session Opened","SoL Session Closed",
    "SoL Enabled","SoL Disabled","KVM Session Started",
    "KVM Session Ended","KVM Enabled","KVM Disabled",
    "VNC Password Failed 3 Times",
    # FW Update
    "Firmware Update Started","Firmware Update Failed",
    # Audit Log
    "Security Audit Log Cleared","Security Audit policy modified",
    "Security Audit Log Disabled","Security Audit Log Enabled",
    "Security Audit Log Exported", "Security Audit Log Recovery",
    # /*Network Time*/
    "AMT Time Set",
    # /*Network Admin*/
    "TCP/IP Parameters Set","Host Name Set","Domain Name Set",
    "VLAN Parameters Set","Link Policy Set","IPv6 parameters Set",
    # /*Storage Admin*/
    "Global Storage Attributes Set","Storage EACL Modified",
    "Storage FPACL Modified","Storage Write Operation",
    # /*Event Manager*/
    "Alert Subscribed","Alert Unsubscribed","Event Log Cleared",
    "Event Log Frozen",
    # /*SD*/
    "SD Filter Added","SD Filter Removed","SD Policy Added",
    "SD Policy Removed","SD Default Policy Set","SD Heuristics Option Set",
    "SD Heuristics State Cleared",
    # /*AP*/
    "Agent Watchdog Added","Agent Watchdog Removed",
    "Agent Watchdog Action set",
    # /*Wireless*/
    "Wireless Profile Added","Wireless Profile Removed",
    "Wireless Profile Updated",
    # /*EAC*/
    "EAC Posture Signer SET","EAC Enabled","EAC Disabled",
    "EAC Posture State Update","EAC Set Options",
    # /*KVM*/
    "KVM opt-in Enabled","KVM opt-in Disabled","KVM password Changed",
    "KVM consent succeeded","KVM consent failed",
    # /*User Opt-In*/
    "Opt-In policy Change",
    "Send Consent Code Event",
    "attempted to send a StartOptIn request, but the request was blocked"]


with open(FILE_TO_DECODE) as fd:
  records = fd.read().splitlines()

parsed_records = []
for record in records:
  d = base64.b64decode(record)

  if DEBUG:
    parsed_record = collections.OrderedDict([("record_size_bytes", len(d))])
  else:
    parsed_record = collections.OrderedDict()

  start_index = 0
  audit_app_id, event_id, init_type = struct.unpack(
      ">HHB", d[start_index:start_index+5])
  start_index = start_index + 5
  parsed_record.update(collections.OrderedDict([
      ("AuditAppID", AuditAppID(audit_app_id).name),
      ("EventID", EventID_list[event_id]),
      ("InitType", InitiatorType(init_type).name)]))

  if init_type == InitiatorType.HTTP_DIGEST.value:
    username_length, = struct.unpack(">B", d[start_index:start_index+1])
    start_index = start_index + 1
    parsed_record["UsernameLength"] = username_length

    if username_length > 0:
      username, = struct.unpack(
          ">%ss" % username_length,
          d[start_index:start_index+username_length])
      start_index = start_index + username_length
      parsed_record["Username"] = username

  elif init_type == InitiatorType.KERBEROS_SID.value:
    pass

  timestamp, mlocation_type, net_addr_length = struct.unpack(
      ">IBB", d[start_index:start_index+6])
  start_index = start_index + 6
  parsed_record["TimeStamp"] = timestamp

  timestamp_readable = datetime.datetime.fromtimestamp(
      int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
  parsed_record.update(collections.OrderedDict([
      ("TimeStamp_readable", timestamp_readable),
      ("MCLocationType", AddressType(mlocation_type).name),
      ("NetAddressLength", net_addr_length)]))

  if net_addr_length > 0:
    net_addr, = struct.unpack(
        ">%ss" % net_addr_length,
        d[start_index:start_index+net_addr_length])
    start_index = start_index + net_addr_length
    parsed_record["NetAddress"] = net_addr

  extended_data_length, = struct.unpack(">B", d[start_index:start_index+1])
  start_index = start_index + 1
  parsed_record["ExtendedDataLength"] = extended_data_length

  if extended_data_length > 0:
    extended_data, = struct.unpack(
        ">%ss" % extended_data_length,
        d[start_index:start_index+extended_data_length])
    start_index = start_index + extended_data_length
    parsed_record["ExtendedData"] = extended_data.decode("latin-1")

  parsed_records.append(parsed_record)

parsed_records.sort(key=lambda item: item["TimeStamp"])
print json.dumps(parsed_records, separators=(",", ": "), indent=2)
