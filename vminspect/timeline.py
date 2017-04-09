# Copyright (c) 2016-2017, Matteo Cafasso
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
from datetime import timedelta
from functools import lru_cache
from itertools import chain, groupby
from tempfile import NamedTemporaryFile
from collections import defaultdict, namedtuple

from vminspect.filesystem import FileSystem
from vminspect.usnjrnl import CorruptedUsnRecord, usn_journal


class FSTimeline:
    def __init__(self, disk):
        self._disk = disk
        self._filesystem = None
        self._filetype_cache = {}
        self._checksum_cache = {}
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

    def timeline(self):
        self.logger.debug("Extracting File System timeline events.")
        events = tuple(Event(d.inode, d.path, d.size, d.allocated, t, r)
                       for d in self._visit_filesystem()
                       for t, r in ((d.atime, 'access'),
                                    (d.mtime, 'change'),
                                    (d.ctime, 'attribute_change'),
                                    (d.crtime, 'creation'))
                       if t > 0)

        self.logger.debug("Sorting File System timeline events.")
        return sorted(events, key=lambda e: e.timestamp)

    @lru_cache(maxsize=None)
    def file(self, path):
        """Identifies the file type.

        Caches the result to reduce overhead on duplicated events.

        """
        return self._filesystem.file(path)

    @lru_cache(maxsize=None)
    def checksum(self, path):
        """Identifies the file type.

        Caches the result to reduce overhead on duplicated events.

        """
        return self._filesystem.checksum(path)

    def _visit_filesystem(self):
        """Walks through the filesystem content."""
        self.logger.debug("Parsing File System content.")

        root_partition = self._filesystem.inspect_get_roots()[0]

        yield from self._root_dirent()

        for entry in self._filesystem.filesystem_walk(root_partition):
            yield Dirent(
                entry['tsk_inode'],
                self._filesystem.path('/' + entry['tsk_name']),
                entry['tsk_size'], entry['tsk_type'],
                True if entry['tsk_flags'] & TSK_ALLOC else False,
                timestamp(entry['tsk_atime_sec'], entry['tsk_atime_nsec']),
                timestamp(entry['tsk_mtime_sec'], entry['tsk_mtime_nsec']),
                timestamp(entry['tsk_ctime_sec'], entry['tsk_ctime_nsec']),
                timestamp(entry['tsk_crtime_sec'], entry['tsk_crtime_nsec']))

    def _root_dirent(self):
        """Returns the root folder dirent as filesystem_walk API doesn't."""
        fstat = self._filesystem.stat('/')

        yield Dirent(fstat['ino'], self._filesystem.path('/'),
                     fstat['size'], 'd', True,
                     timestamp(fstat['atime'], 0),
                     timestamp(fstat['mtime'], 0),
                     timestamp(fstat['ctime'], 0),
                     0)


class NTFSTimeline(FSTimeline):
    """Inspect NTFS filesystem in order to extract a timeline of events
    containing the information related to files/directories changes.

    This feature depends on a special build of Libguestfs available at:
      https://github.com/noxdafox/libguestfs/tree/forensics

    """
    def __init__(self, disk):
        super().__init__(disk)

    def __enter__(self):
        super().__enter__()

        if self._filesystem.osname != 'windows':
            self._filesystem.umount()

            raise RuntimeError("Filesystem is not NTFS.")

        return self

    def usnjrnl_timeline(self):
        """Iterates over the changes occurred within the filesystem.

        Yields UsnJrnlEvent namedtuples containing:

            file_reference_number: known in Unix FS as inode.
            path: full path of the file.
            size: size of the file in bytes if recoverable.
            allocated: whether the file exists or it has been deleted.
            timestamp: timespamp of the change.
            changes: list of changes applied to the file.
            attributes: list of file attributes.

        """
        content = defaultdict(list)

        self.logger.debug("Extracting Update Sequence Number journal.")
        journal = self._read_journal()

        for dirent in self._visit_filesystem():
            content[dirent.inode].append(dirent)

        self.logger.debug("Generating timeline.")
        yield from generate_timeline(journal, content)

    def _read_journal(self):
        """Extracts the USN journal from the disk and parses its content."""
        root = self._filesystem.inspect_get_roots()[0]
        inode = self._filesystem.stat('C:\\$Extend\\$UsnJrnl')['ino']

        with NamedTemporaryFile(buffering=0) as tempfile:
            self._filesystem.download_inode(root, inode, tempfile.name)

            journal = usn_journal(tempfile.name)

            return parse_journal(journal)


def parse_journal(journal):
    """Parses the USN Journal content removing duplicates
    and corrupted records.

    """
    events = [e for e in journal if not isinstance(e, CorruptedUsnRecord)]
    keyfunc = lambda e: str(e.file_reference_number) + e.file_name + e.timestamp
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

            yield UsnJrnlEvent(
                dirent.inode, dirent.path, dirent.size, dirent.allocated,
                event.timestamp, event.changes, event.attributes)
        except LookupError as error:
            LOGGER.debug(error)


def lookup_dirent(event, content):
    for dirent in content[event.inode]:
        if dirent.path.endswith(event.name):
            return dirent

    # try constructing the full path from the parent folder
    for dirent in content[event.parent_inode]:
        if dirent.type == 'd':
            return Dirent(event.inode, ntpath.join(dirent.path, event.name), -1,
                          None, False, 0, 0, 0, 0)
    else:
        raise LookupError("File %s not found" % event.name)


def timestamp(secs, nsecs):
    delta = timedelta(seconds=secs) + timedelta(microseconds=(nsecs / 1000))

    return delta.total_seconds()


TSK_ALLOC = 0x01


Event = namedtuple('Event',
                   ('inode', 'path', 'size',
                    'allocated', 'timestamp', 'reason'))
UsnJrnlEvent = namedtuple('Event', ('file_reference_number', 'path', 'size',
                                    'allocated', 'timestamp', 'changes',
                                    'attributes'))

Dirent = namedtuple('Dirent', ('inode', 'path', 'size', 'type', 'allocated',
                               'atime', 'mtime', 'ctime', 'crtime'))
JrnlEvent = namedtuple('JrnlEvent', ('inode', 'parent_inode', 'name',
                                     'timestamp', 'changes', 'attributes'))

LOGGER = logging.getLogger("%s" % (__name__))
