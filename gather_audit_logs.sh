#!/bin/bash
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

AMT_HOST=localhost
AMT_USER="\$\$OsAdmin"
AMT_PASSWORD=`sudo python ./amt_local_sys_account.py`

url="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuditLog"

no_of_records=`wsman get $url -h ${AMT_HOST} -P 16992 -u ${AMT_USER} -p ${AMT_PASSWORD} | egrep CurrentNumberOfRecords | cut -d\> -f2 | cut -d\< -f1`


rm -f audit_log.log.tmp

for ((i = 1; i <= no_of_records; i=i+9));
do
  wsman invoke -a ReadRecords -k StartIndex=$i $url -h ${AMT_HOST} -P 16992 -u ${AMT_USER} -p ${AMT_PASSWORD} >> audit_log.log.tmp
  sleep 0.5
done

egrep "EventRecords" audit_log.log.tmp | cut -d\> -f2 | cut -d\< -f1 | sort | uniq > audit_log.log

# USE the audit_log.log with decode_amt_auditlog.py to decode.
