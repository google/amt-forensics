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
AMT_USER=admin
AMT_PASSWORD=your_amt_password_you_set_at_provisionig_time

echo $AMT_USER

echo "Identify the host"
echo "------"
wsman identify -h ${AMT_HOST} -P 16992 -u admin -p ${AMT_PASSWORD}
echo "------"

while read class; do
  if [[ $class == "AMT_"* ]]
  then
    url="http://intel.com/wbem/wscim/1/amt-schema/1/$class"
  elif [[ $class == "CIM_"* ]]
  then
    url="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/$class"
  else [[ $class == "IPS_"* ]]
    url="http://intel.com/wbem/wscim/1/ips-schema/1/$class"
  fi

  echo "======================================="
  echo "get $class"
  echo "------"
  wsman get $url -h ${AMT_HOST} -P 16992 -u ${AMT_USER} -p ${AMT_PASSWORD}
  echo "------"
  echo "enumerate -M epr $class"
  echo "------"
  wsman -M epr enumerate $url -h ${AMT_HOST} -P 16992 -u ${AMT_USER} -p ${AMT_PASSWORD}
  echo "------"
  echo "enumerate $class"
  echo "------"
  wsman enumerate $url -h ${AMT_HOST} -P 16992 -u ${AMT_USER} -p ${AMT_PASSWORD}
  echo "------"
done <ws-man-class-list.txt

echo "======================================="
