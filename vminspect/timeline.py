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


"""Analyse disk content to extract File System event timelines."""

import ntpath
import logging
from itertools import chain, groupby
from tempfile import NamedTemporaryFile
from collections import defaultdict, namedtuple

from vminspect.filesystem import FileSystem
from vminspect.usnjrnl import CorruptedUsnRecord, usn_journal


Event = namedtuple('Event', ('file_reference_number', 'path', 'size',
                             'allocated', 'timestamp', 'changes', 'attributes'))


class NTFSTimeline(FileSystem):
    """Inspect NTFS filesystem in order to extract a timeline of events
    containing the information related to files/directories changes.

    This feature depends on a special build of Libguestfs available at:
      https://github.com/noxdafox/libguestfs/tree/forensics

    """
    def __init__(self, disk_path):
        super().__init__(disk_path)
        self.logger = logging.getLogger(
            "%s.%s" % (self.__module__, self.__class__.__name__))

    def timeline(self):
        """Iterates over the changes occurred within the filesystem.

        Yields Event namedtuples containing:

            file_reference_number: known in Unix FS as inode.
            path: full path of the file.
            size: size of the file in bytes if recoverable.
            allocated: whether the file exists or it has been deleted.
            timestamp: timespamp of the change.
            changes: list of changes applied to the file.
            attributes: list of file attributes.

        """
        self.logger.debug("Extracting Update Sequence Number journal.")
        journal = self._read_journal()

        self.logger.debug("Parsing File System content.")
        content = self._visit_filesystem()

        self.logger.debug("Generating timeline.")
        yield from generate_timeline(journal, content)

    def _read_journal(self):
        """Extracts the USN journal from the disk and parses its content."""
        root = self.guestfs.inspect_get_roots()[0]
        inode = self.stat('C:\\$Extend\\$UsnJrnl')['ino']

        with NamedTemporaryFile(buffering=0) as tempfile:
            self.guestfs.download_inode(root, inode, tempfile.name)

            journal = usn_journal(tempfile.name)

            return parse_journal(journal)

    def _visit_filesystem(self):
        """Walks through the filesystem content and generates
        a map inode -> file info.

        """
        content = defaultdict(list)
        root_partition = self.guestfs.inspect_get_roots()[0]

        inode, dirent = self._root_dirent()
        content[inode].append(dirent)

        for entry in self.guestfs.filesystem_walk(root_partition):
            dirent = Dirent(self.path('/' + entry['tsk_name']),
                            entry['tsk_size'],
                            entry['tsk_type'],
                            entry['tsk_flags'] == 1 and True or False)

            content[entry['tsk_inode']].append(dirent)

        return content

    def _root_dirent(self):
        """Returns the root folder dirent as filesystem_walk API doesn't."""
        fstat = self.stat('C:\\')

        return fstat['ino'], Dirent(self.path('/'), fstat['size'], 'd', True)


def parse_journal(journal):
    """Parses the USN Journal content removing duplicates
    and corrupted records.

    """
    events = [e for e in journal if not isinstance(e, CorruptedUsnRecord)]
    keyfunc = lambda e: e.file_name + e.timestamp
    event_groups = (tuple(g) for k, g in groupby(events, key=keyfunc))

    if len(events) < len(list(journal)):
        LOGGER.debug(
            "Corrupted records in UsnJrnl, some events might be missing.")

    return [journal_event(g) for g in event_groups]


def journal_event(events):
    """Group multiple events into a single one."""
    reasons = set(chain.from_iterable(e.reasons for e in events))
    attributes = set(chain.from_iterable(e.file_attributes for e in events))

    return JrnlEvent(events[0].file_reference_number,
                     events[0].parent_file_reference_number,
                     events[0].file_name,
                     events[0].timestamp,
                     list(reasons), list(attributes))


def generate_timeline(usnjrnl, content):
    """Aggregates the data collected from the USN journal
    and the filesystem content.

    """
    for event in usnjrnl:
        try:
            dirent = lookup_dirent(event, content)

            yield Event(event.inode, dirent.path, dirent.size, dirent.allocated,
                        event.timestamp, event.changes, event.attributes)
        except LookupError as error:
            LOGGER.debug(error)


def lookup_dirent(event, content):
    for dirent in content[event.inode]:
        if event.name in dirent.path:
            return dirent

    # try constructing the full path from the parent folder
    for dirent in content[event.parent_inode]:
        if dirent.type == 'd':
            return Dirent(ntpath.join(dirent.path, event.name), -1, None, False)
    else:
        raise LookupError("File %s not found" % event.name)


LOGGER = logging.getLogger("%s" % (__name__))

JrnlEvent = namedtuple('JrnlEvent', ('inode', 'parent_inode', 'name',
                                     'timestamp', 'changes', 'attributes'))
Dirent = namedtuple('Dirent', ('path', 'size', 'type', 'allocated'))
