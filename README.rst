VMInspect
=========

A collection of helpers for inspecting Virtual Machine disk images.

Useful for computer forensics analysis and for tests validation.

Disclaimers
-----------

Even though all the precautions have been taken, if misused this library can cause corruption and data loss within the disk images. Always make a copy of the disk images before analysing them.

The author is not responsible for any damage or data loss deriving from the usage of this tool.

Analysing disk images may take several minutes and quite many of resources from the computer.

The availability of hardware acceleration (KVM) as well as the use of concurrency speed up the process quite sensitively.

Dependencies
------------

Python 3: https://www.python.org/

libguestfs: http://libguestfs.org/

hivex: http://libguestfs.org/hivex.3.html

Pebble: https://pypi.python.org/pypi/Pebble

Requests: https://pypi.python.org/pypi/requests/


Examples
--------

List all the files contained within a disk image.

::

    vminspect list ubuntu.raw --identify --size

    [
      {
        "size": 986672,
        "path": "/bin/bash",
        "sha1": "a042aad4ee0b472285ca2685dcaab0c3e1b1046d",
        "type": "ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), ... "
      },
      {
        "size": 15481,
        "path": "/etc/cron.daily/apt",
        "sha1": "0582163ff58be6b4984afa8b12426834de3c0175",
        "type": "POSIX shell script, ASCII text executable"
      },
      ...
    ]

Compare two disk images. ZeroAccess malware on Windows 7.

Highlighted the executable dropping location and two libraries (32 and 64 bit versions) disguised as Desktop.ini files as well as the deletion of Windows Defender related files.

On the Windows Registry is visible how the malware ensures its execution at machine's startup.

::

   vminspect compare --identify --registry windows7.qcow2 windows7zeroaccess.qcow2

   {
     "created_files": [
       {
         "path": "C:\\Program Files (x86)\\Google\\Desktop\\Install\\ ... \\GoogleUpdate.exe",
         "sha1": "0bac2335d46d89b55836ffda2f41e5b9a29cb3c4",
         "type": "PE32 executable (GUI) Intel 80386",
       },
       {
         "path": "C:\\Windows\\assembly\\GAC_32\\Desktop.ini",
         "sha1": "f3ca92972bbf1fa97e39ba265127d7f12b9d2575",
         "type": "PE32 executable (DLL) (GUI) Intel 80386",
       },
       {
         "path": "C:\\Windows\\assembly\\GAC_64\\Desktop.ini",
         "sha1": "b8834d7be89e71b41e2265976841873c079e5dd5",
         "type": "PE32+ executable (DLL) (GUI) x86-64",
       },
       ...
     ],
     "deleted_files": [
       {
         "path": "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
         "original_sha1": "2ae2a6b863616b61ccb550fc1a145ae025896de1"
         "type": "PE32+ executable (GUI) x86-64",
       },
       {
         "path": "C:\\Program Files\\Windows Defender\\MpEvMsg.dll",
         "original_sha1": "7c17071459c80d4b0bd14cc31ac94306d7cc3c24"
         "type": "PE32+ executable (DLL) (GUI) x86-64",
       },
       ...
     ],
     ...
     "registry": {
       "created_keys": {
         "\\HKLM\\ControlSet001\\services\\\u202eetadpug": [
           ["ImagePath", "REG_SZ", "C:\\Program Files (x86)\\Google\\Desktop\\Install\\ ... \\GoogleUpdate.exe"],
           ["DisplayName", "REG_SZ", "Google Update Service (gupdate)"],
           ["Start", "REG_DWORD", "2"],
           ...
         ],
         ...
       },
       ...
     }
   }

Query Virustotal regarding the content of a disk.

::

   vminspect vtscan <VT API key> --type "EICAR.*" ubuntu.qcow2

   [
     {
       "name": "/home/user/eicar.txt",
       "hash": "cf8bd9dfddff007f75adf4c2be48005cea317c62",
       "detections": {
         "Tencent": {
           "version": "1.0.0.1",
           "detected": true,
           "update": "20160515",
           "result": "EICAR.TEST.NOT-A-VIRUS"
         },
         "Symantec": {
           "version": "20151.1.0.32",
           "detected": true,
           "update": "20160515",
           "result": "EICAR Test String"
         },
       }
   ...

Query a CVE database for vulnerable applications.

::

   vminspect vulnscan http://cve.circl.lu/api/search ubuntu.qcow2

   [
     {
       "name": "gnupg",
       "version": "1.4.16",
       "vulnerabilities": [
         [
           "CVE-2014-4617",
           "The do_uncompress function in g10/compress.c ..."
         ]
       ]
     },
     {
       "name": "openssl",
       "version": "1.0.1f",
       "vulnerabilities": [
         [
           "CVE-2016-2842",
           "The doapr_outch function in crypto/bio/b_print.c in OpenSSL 1.0.1 ..."
         ],
   ...

Extract event timelines of NTFS disks. Installation of 7Zip on Windows 7.

::

   vminspect timeline --identify --hash windows7.qcow2

   {
     "file_reference_number": 60228,
     "path": "C:\\Program Files\\7-Zip\\7z.dll",
     "size": 1592320,
     "allocated": true,
     "timestamp": "2016-05-07 07:42:49.518554",
     "changes": [
       "BASIC_INFO_CHANGE",
       "DATA_EXTEND",
       "FILE_CREATE",
       "CLOSED"
     ],
     "attributes": [
       "ARCHIVE"
     ],
     "type": "PE32+ executable (DLL) (GUI) x86-64, for MS Windows",
     "hash": "d467f1f7a8407d1650060c8fe3dc6a0ccff4d409"
   },
   {
     "file_reference_number": 60229,
     "path": "C:\\Program Files\\7-Zip\\7z.exe",
     "size": 447488,
     "allocated": true,
     "timestamp": "2016-05-07 07:42:49.518554",
     "changes": [
       "BASIC_INFO_CHANGE",
       "DATA_EXTEND",
       "FILE_CREATE",
       "CLOSED"
     ],
     "attributes": [
       "ARCHIVE"
     ],
     "type": "PE32+ executable (console) x86-64, for MS Windows",
     "hash": "7447eb123655792fede586ad049ac737effa9e6c"
   }
