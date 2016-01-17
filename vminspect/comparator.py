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


"""Module for comparing Virtual Machine Disk Images."""


import os
import logging
from pebble import thread
from collections import defaultdict

from vminspect.winreg import compare_registries
from vminspect.utils import posix_path, makedirs
from vminspect.filesystem import FileSystem, add_file_type, add_file_size


class DiskComparator:
    """Performs an in depth comparison of two given disk images."""
    def __init__(self, disk0, disk1):
        self.disks = (disk0, disk1)
        self.filesystems = ()
        self._comparison = {}
        self.logger = logging.getLogger(
            "%s.%s" % (self.__module__, self.__class__.__name__))

    def __enter__(self):
        self.filesystems = (FileSystem(self.disks[0]),
                            FileSystem(self.disks[1]))

        for filesystem in self.filesystems:
            filesystem.mount_disk()

        return self

    def __exit__(self, *_):
        for filesystem in self.filesystems:
            filesystem.umount_disk()

    def compare(self, concurrent=False, identify=False, size=False):
        """Compares the two disks according to flags.

        Generates the following report:

            {'created_files': [{'path': '/file/in/disk1/not/in/disk0',
                                'sha1': 'sha1_of_the_file'}],
             'deleted_files': [{'path': '/file/in/disk0/not/in/disk1',
                                'original_sha1': 'sha1_of_the_file'}],
             'modified_files': [{'path': '/file/both/disks/but/different',
                                 'sha1': 'sha1_of_the_file_on_disk0',
                                 'original_sha1': 'sha1_of_the_file_on_disk0'}]}

        If concurrent is set to True, the logic will use multiple CPUs to
        speed up the process.

        The identify and size keywords will add respectively the type
        and the size of the files to the results.

        """
        self.logger.debug("Comparing FS contents.")
        results = compare_filesystems(*self.filesystems, concurrent=concurrent)

        if identify:
            self.logger.debug("Gatering file types.")
            results = files_type(results, *self.filesystems)

        if size:
            self.logger.debug("Gatering file sizes.")
            results = files_size(results, *self.filesystems)

        return results

    def extract(self, disk, files, path='.'):
        """Extracts the given files from the given disk.

        Disk must be an integer (1 or 2) indicating from which of the two disks
        to extract.

        Files must be a list of dictionaries containing
        the keys 'path' and 'sha1'.

        Files will be extracted in path and will be named with their sha1.

        Returns a dictionary.

            {'extracted_files': [<sha1>, <sha1>],
             'extraction_errors': [<sha1>, <sha1>]}

        """
        self.logger.debug("Extracting files.")
        extracted_files, failed = self._extract_files(disk, files, path)

        return {'extracted_files': [f for f in extracted_files.keys()],
                'extraction_errors': [f for f in failed.keys()]}

    def compare_registry(self, concurrent=False):
        self.logger.debug("Comparing Windows registries.")

        self._assert_windows()

        return compare_registries(*self.filesystems, concurrent=concurrent)

    def _extract_files(self, disk, files, path):
        path = os.path.join(path, 'extracted_files')

        makedirs(path)

        extracted, failed = extract_files(self.filesystems[disk], files, path)

        self.logger.info("Files extracted into %s.", path)
        if failed:
            self.logger.warning(
                "The following files could not be extracted: %s",
                '\n'.join(failed.values()))

        return extracted, failed

    def _assert_windows(self):
        if not all((fs.osname == 'windows' for fs in self.filesystems)):
            raise RuntimeError("Both disks must contain a Windows File System")


def compare_filesystems(fs0, fs1, concurrent=False):
    """Compares the two given filesystems.

    fs0 and fs1 are two mounted GuestFS instances
    containing the two disks to be compared.

    If the concurrent flag is True,
    two processes will be used speeding up the comparison on multiple CPUs.

    Returns a dictionary containing files created, removed and modified.

        {'created_files': [<files in fs1 and not in fs0>],
         'deleted_files': [<files in fs0 and not in fs1>],
         'modified_files': [<files in both fs0 and fs1 but different>]}

    """
    if concurrent:
        task0 = thread.concurrent(target=visit_filesystem, args=(fs0, ))
        task1 = thread.concurrent(target=visit_filesystem, args=(fs1, ))

        files0 = task0.get()
        files1 = task1.get()
    else:
        files0 = visit_filesystem(fs0)
        files1 = visit_filesystem(fs1)

    return compare_files(dict(files0), dict(files1))


def compare_files(files0, files1):
    """Compares two dictionaries of files returning their difference.

        {'created_files': [<files in files1 and not in files0>],
         'deleted_files': [<files in files0 and not in files1>],
         'modified_files': [<files in both files0 and files1 but different>]}

    """
    results = defaultdict(list)

    for path, sha1 in files1.items():
        if path in files0:
            if sha1 != files0[path]:
                results['modified_files'].append(
                    {'path': path,
                     'original_sha1': files0[path],
                     'sha1': sha1})
        else:
            results['created_files'].append({'path': path,
                                             'sha1': sha1})
    for path, sha1 in files0.items():
        if path not in files1:
            results['deleted_files'].append({'path': path,
                                             'original_sha1': files0[path]})

    return results


def extract_files(filesystem, files, path):
    """Extracts requested files.

    files must be a list of files in the format

        {"C:\\Windows\\System32\\NTUSER.DAT": "sha1_hash"} for windows
        {"/home/user/text.txt": "sha1_hash"} for other FS.

    files will be extracted into path which must exist beforehand.

    Returns two dictionaries:

        {"sha1": "/local/path/sha1"} files successfully extracted
        {"sha1": "C:\\..\\text.txt"} files which could not be extracted windows
        {"sha1": "/../text.txt"} files which could not be extracted linux

    """
    extracted_files = {}
    failed_extractions = {}

    for file_to_extract in files:
        source = posix_path(file_to_extract['path'])
        destination = os.path.join(path, file_to_extract['sha1'])

        if not os.path.exists(destination):
            try:
                filesystem.download(source, destination)
                extracted_files[file_to_extract['sha1']] = destination
            except RuntimeError:
                failed_extractions[file_to_extract['sha1']] = source
        else:
            extracted_files[file_to_extract['sha1']] = destination

    return extracted_files, failed_extractions


def visit_filesystem(filesystem):
    """Utility function for running the files iterator at once.

    Returns a dictionary.

        {'/path/on/filesystem': 'file_hash'}

    """
    return dict(filesystem.files('/'))


def files_type(files, fs0, fs1):
    """Inspects the file type of the given files."""
    files['deleted_files'] = add_file_type(fs0, files['deleted_files'])
    for key in ('created_files', 'modified_files'):
        files[key] = add_file_type(fs1, files[key])

    return files


def files_size(files, fs0, fs1):
    """Gets the file size of the given files."""
    files['deleted_files'] = add_file_size(fs0, files['deleted_files'])
    for key in ('created_files', 'modified_files'):
        files[key] = add_file_size(fs1, files[key])

    return files
