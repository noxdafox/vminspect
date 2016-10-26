# Copyright (c) 2016, Matteo Cafasso
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.

# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


"""Module for parsing Windows Event Log files."""


import logging
from tempfile import NamedTemporaryFile

from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view
from vminspect.filesystem import FileSystem


class WinEventLog:
    """WinEventLog class.

    Allows to retrieve the Events contained within Windows Event Log files.

    """
    def __init__(self, disk):
        self._disk = disk
        self._filesystem = None
        self.logger = logging.getLogger(
            "%s.%s" % (self.__module__, self.__class__.__name__))

    def __enter__(self):
        self._filesystem = FileSystem(self._disk)
        self._filesystem.mount()

        return self

    def __exit__(self, *_):
        self._filesystem.umount()

    def __getattr__(self, attr):
        return getattr(self._filesystem, attr)

    def eventlog(self, path):
        """Iterates over the Events contained within the log at the given path.

        For each Event, yields a XML string.

        """
        self.logger.debug("Parsing Event log file %s.", path)

        with NamedTemporaryFile(buffering=0) as tempfile:
            self._filesystem.download(path, tempfile.name)

            file_header = FileHeader(tempfile.read(), 0)

            for xml_string, _ in evtx_file_xml_view(file_header):
                yield xml_string
