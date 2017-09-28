# AMT Forensics for Linux

This README contains instructions on how to use the scripts in this repository
to retrieve Intel AMT's Audit Log from a Linux machine without knowing the
**admin** user's password. The ideas from the script can be used to retrieve
other pertinent information from Intel AMT via the ME Interface (MEI).

[TOC]

## Prerequisites

1. Linux machine with a provisioned AMT
  * For testing, you can [manually
provision](https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/WordDocuments/manualsetupandconfigurationfromrelease60.htm)
AMT yourself in 10 steps.
  * Make sure ```/dev/mei``` exists.
     * You may need to ```sudo ln -s /dev/mei0 /dev/mei```.
     * If this doesn't exist then this most likely means AMT is not
       enabled & provisioned.

2. Python & OpenWSMAN installed
  * Python 2.7 with python-enum34 (```sudo apt-get install python-enum34```)
  * The ```wsman``` binary in $PATH:
     * ```sudo apt-get install wsmancli```
     * For other platforms see https://openwsman.github.io/

## Setup

The Local Manageability Service (LMS) for Linux needs to built and started:

1. Download [lms-8.0.0-7.tar.gz](https://software.intel.com/en-us/file/lms-800-7targz)
   and unzip it. You can read more info about LMS for Linux
   [here](https://software.intel.com/en-us/articles/download-the-latest-intel-amt-open-source-drivers).
2. Copy lms.patch from this repository into the unziped directory.
3. Carry out the following commands:

```shell
user@host:~/Downloads/lms-8.0.0-7$ patch -p1 < lms.patch
user@host:~/Downloads/lms-8.0.0-7$ chmod u+x configure
user@host:~/Downloads/lms-8.0.0-7$ ./configure --enable-daemon=no
user@host:~/Downloads/lms-8.0.0-7$ # fix problems and re-run until all OK.
user@host:~/Downloads/lms-8.0.0-7$ make
user@host:~/Downloads/lms-8.0.0-7$ sudo src/lms
```

You should be able to load http://localhost:16992/ in your browser now.

Note: On some machines, restarting lms and/or machine is required.

If problems continue, re-try with **debugging** enabled:

```shell
user@host:~/Downloads/lms-8.0.0-7$ make clean
user@host:~/Downloads/lms-8.0.0-7$ ./configure --enable-debug --enable-daemon=no
user@host:~/Downloads/lms-8.0.0-7$ make
user@host:~/Downloads/lms-8.0.0-7$ sudo src/lms
```


## Usage

Once LMS is successfully running as per above, start a new shell:

```shell
user@host:~$ cd amt-forensics/
user@host:~/amt-forensics$ chmod u+x gather_audit_logs.sh
user@host:~/amt-forensics$ sudo ls # gather_audit_logs.sh does a hidden sudo
user@host:~/amt-forensics$ ./gather_audit_logs.sh
user@host:~/amt-forensics$ python ./decode_amt_auditlog.py > decoded_log.txt
user@host:~/amt-forensics$ cat decoded_log.txt # Sample Output as example.
[
  {
    "AuditAppID": "NETWORK_TIME_APPID",
    "EventID": "AMT Provisioning Started",
    "InitType": "HTTP_DIGEST",
    "UsernameLength": 9,
    "Username": "$$OsAdmin",
    "TimeStamp": 1072922804,
    "TimeStamp_readable": "2004-01-01 03:06:44",
    "MCLocationType": "IPV4_ADDR",
    "NetAddressLength": 9,
    "NetAddress": "127.0.0.1",
    "ExtendedDataLength": 4,
    "ExtendedData": "V\"\u00b8\u009c"
  },
  {
    "AuditAppID": "SECURITY_ADMIN_APPID",
    "EventID": "AMT Provisioning Started",
    "InitType": "LOCAL_INITIATOR",
    "TimeStamp": 1506659359,
    "TimeStamp_readable": "2017-09-29 06:29:19",
    "MCLocationType": "NONE",
    "NetAddressLength": 0,
    "ExtendedDataLength": 0
  }
]
user@host:~/amt-forensics$
```

## Web Interface Login

To login via http://localhost:16992/logon.htm, you can
obtain password for the user **$$osAdmin** as per follows:

```shell
user@host:~/amt-forensics$ sudo python amt_local_sys_account.py
[Password String]
user@host:~/amt-forensics$
```

You can then use the username **$$osAdmin** and the printed password
string to login.

## Info from all APIs

The ```getallinfo.sh``` script under the ```all_api_calls``` directory will
attempt to gather info from all available AMT WSMAN APIs. This can be useful
for manual searching & inspiration during forensics.

