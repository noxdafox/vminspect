VMInspect
=========

:Source: https://github.com/noxdafox/vminspect
:Documentation: https://vminspect.readthedocs.io
:Download: https://pypi.python.org/pypi/vminspect

|docs badge|

.. |docs badge| image:: https://readthedocs.org/projects/vminspect/badge/?version=latest
   :target: https://vminspect.readthedocs.io
   :alt: Documentation Status

A collection of helpers for inspecting Virtual Machine disk images.

Useful for computer forensics analysis and for tests validation.

Disclaimers
-----------

Even though all the precautions have been taken, if misused this library can cause corruption and data loss within the disk images. Always make a copy of the disk images before analysing them.

The author is not responsible for any damage or data loss deriving from the usage of this tool.

Analysing disk images may take several minutes a fair amount of computation resources.

To improve analysis speed, ensure Hardware Acceleration (KVM) is enable on the host.

Dependencies
------------

Python 3: https://www.python.org/

libguestfs: http://libguestfs.org/

hivex: http://libguestfs.org/hivex.3.html

Pebble: https://pypi.python.org/pypi/Pebble

Requests: https://pypi.python.org/pypi/requests/

Python Evtx: https://pypi.python.org/pypi/python-evtx/
