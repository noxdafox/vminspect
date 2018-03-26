VMInspect
=========

VMInspect is a set of tools developed in Python for disk forensic analysis. It provides APIs and a command line tool for analysing disk images of various formats.

VMInspect focuses on disk analysis automation and on safely supporting multiple file systems and multiple disk formats.

Design principles
-----------------

VMInspect relies on `Libguestfs <http://libguestfs.org//>`_ tool for analysing the disk images.
Libguestfs employs a small Linux VM (QEMU/KVM) in order to mount the disk images and offers a pretty complete API to operate over them.

Most of the available forensic tools are struggling to support the multitude of disk image formats out there. Their communities are building custom modules capable of interpreting specific file formats such as QCOW and VMDK. Quite a lot of development resources are allocated to maintain such modules. VMInspect delegates the issue to the hypervisor technology which is better suited to handle this kind of problems.

Same issue applies with file system formats. The Linux OS offers a decent support to a large amount of file systems.

Moreover, analysis tools are affected by vulnerabilities which might be exploited. The problem becomes more relevant if the analysis is to be automated as the analyst is not in full control of the process anymore. The hypervisor provides a layer of security for the analysis system. If one of the tools gets compromised, the damages will be limited to the small Linux VM rather than the whole host.

Thanks to the flexibility of Libguestfs, it's fairly easy to integrate forensic tools within the VM quickly expanding its set of features.

Contents:

.. toctree::
   :maxdepth: 2

   examples
   modules


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
