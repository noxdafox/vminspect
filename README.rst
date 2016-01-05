VMInspect
=========

A collection of helpers for inspecting Virtual Machine disk images.

Useful for computer forensics analysis and for tests validation.

Disclaimers
-----------

Even though all the precautions have been taken, if misused this library can cause corruption and data loss within the disk images. Always make a copy of the disk images before analysing them.

The author is not responsible for any damage or data loss deriving from the usage of this tool.

Analysing disk images may take several minutes and lots of resources from the computer.

The availability of hardware acceleration (KVM) as well as the use of concurrency speed up the process quite sensitively.

Dependencies
------------

Python 3: https://www.python.org/

libguestfs: http://libguestfs.org/

Pebble: https://pypi.python.org/pypi/Pebble


Examples
--------

List all the files contained within a disk image.

::

    python inspect.py list ubuntu.raw --identify --size

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

Compare two disk images. Installation of lynx browser on Ubuntu.

::

   python inspect.py compare --identify ubuntu.qcow2 ubuntu_lynx.qcow2

   {
     "created_files": [
       {
         "type": "ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV) ... ",
         "sha1": "d4365bec7d0bc68d6fc84718a2b46801de00196d",
         "path": "/usr/bin/lynx"
       },
       {
        "type": "ASCII text",
        "sha1": "1e589381fd480138fb43f57dafca5e04cffb67f7",
        "path": "/etc/lynx-cur/lynx.cfg"
       },
       {
         "type": "troff or preprocessor input, ASCII text (gzip compressed data, ... )",
         "sha1": "7b8af1510461fd2f448d857e6de32f95c0d8e835",
         "path": "/usr/share/man/man1/lynx.1.gz"
       },
       ...
     ]
     ...
   }

Compare two disk images. ZeroAccess malware on Windows 7.
Highlighted the executable dropping location and two libraries (32 and 64 bit versions) disguised as Desktop.ini files as well as the deletion of Windows Defender related files.

::

   python inspect.py compare --identify windows7.qcow2 windows7zeroaccess.qcow2

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
     ]
     ...
   }
