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

Documentation
-------------

https://pythonhosted.org/vminspect/


Examples
--------

https://pythonhosted.org/vminspect/examples.html
