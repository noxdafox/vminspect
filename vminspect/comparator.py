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


import logging
from itertools import chain
from pebble import concurrent
from pathlib import Path, PurePath
from tempfile import NamedTemporaryFile

from vminspect.filesystem import FileSystem
from vminspect.winreg import RegistryHive, registry_root
from vminspect.winreg import user_registries_path, registries_path


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
            filesystem.mount()

        return self

    def __exit__(self, *_):
        for filesystem in self.filesystems:
            filesystem.umount()

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
        results = compare_filesystems(self.filesystems[0], self.filesystems[1],
                                      concurrent=concurrent)

        if identify:
            self.logger.debug("Gatering file types.")
            results = files_type(self.filesystems[0], self.filesystems[1],
                                 results)

        if size:
            self.logger.debug("Gatering file sizes.")
            results = files_size(self.filesystems[0], self.filesystems[1],
                                 results)

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
        """Compares the Windows Registry contained within the two File Systems.

        It parses all the registry hive files contained within the disks
        and generates the following report.

            {'created_keys': {'\\Reg\\Key': (('Key', 'Type', 'Value'))}
             'deleted_keys': ['\\Reg\\Key', ...],
             'created_values': {'\\Reg\\Key': (('Key', 'Type', 'NewValue'))},
             'deleted_values': {'\\Reg\\Key': (('Key', 'Type', 'OldValue'))},
             'modified_values': {'\\Reg\\Key': (('Key', 'Type', 'NewValue'))}}

        Only registry hives which are contained in both disks are compared.
        If the second disk contains a new registry hive,
        its content can be listed using winreg.RegistryHive.registry() method.

        If the concurrent flag is True,
        two processes will be used speeding up the comparison on multiple CPUs.

        """
        self.logger.debug("Comparing Windows registries.")

        self._assert_windows()

        return compare_registries(self.filesystems[0], self.filesystems[1],
                                  concurrent=concurrent)

    def _extract_files(self, disk, files, path):
        path = str(PurePath(path, 'extracted_files'))

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
        future0 = concurrent_visit_filesystem(fs0)
        future1 = concurrent_visit_filesystem(fs1)

        files0 = future0.result()
        files1 = future1.result()
    else:
        files0 = visit_filesystem(fs0)
        files1 = visit_filesystem(fs1)

    return file_comparison(files0, files1)


def file_comparison(files0, files1):
    """Compares two dictionaries of files returning their difference.

        {'created_files': [<files in files1 and not in files0>],
         'deleted_files': [<files in files0 and not in files1>],
         'modified_files': [<files in both files0 and files1 but different>]}

    """
    comparison = {'created_files': [],
                  'deleted_files': [],
                  'modified_files': []}

    for path, sha1 in files1.items():
        if path in files0:
            if sha1 != files0[path]:
                comparison['modified_files'].append(
                    {'path': path,
                     'original_sha1': files0[path],
                     'sha1': sha1})
        else:
            comparison['created_files'].append({'path': path,
                                                'sha1': sha1})
    for path, sha1 in files0.items():
        if path not in files1:
            comparison['deleted_files'].append({'path': path,
                                                'original_sha1': files0[path]})

    return comparison


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
        source = file_to_extract['path']
        destination = Path(path, file_to_extract['sha1'])

        if not destination.exists():
            destination = str(destination)

            try:
                filesystem.download(source, destination)
                extracted_files[file_to_extract['sha1']] = destination
            except RuntimeError:
                failed_extractions[file_to_extract['sha1']] = source
        else:
            extracted_files[file_to_extract['sha1']] = destination

    return extracted_files, failed_extractions


def compare_registries(fs0, fs1, concurrent=False):
    """Compares the Windows Registry contained within the two File Systems.

    If the concurrent flag is True,
    two processes will be used speeding up the comparison on multiple CPUs.

    Returns a dictionary.

        {'created_keys': {'\\Reg\\Key': (('Key', 'Type', 'Value'), ...)}
         'deleted_keys': ['\\Reg\\Key', ...],
         'created_values': {'\\Reg\\Key': (('Key', 'Type', 'NewValue'), ...)},
         'deleted_values': {'\\Reg\\Key': (('Key', 'Type', 'OldValue'), ...)},
         'modified_values': {'\\Reg\\Key': (('Key', 'Type', 'NewValue'), ...)}}

    """
    hives = compare_hives(fs0, fs1)

    if concurrent:
        future0 = concurrent_parse_registries(fs0, hives)
        future1 = concurrent_parse_registries(fs1, hives)

        registry0 = future0.result()
        registry1 = future1.result()
    else:
        registry0 = parse_registries(fs0, hives)
        registry1 = parse_registries(fs1, hives)

    return registry_comparison(registry0, registry1)


def registry_comparison(registry0, registry1):
    """Compares two dictionaries of registry keys returning their difference."""
    comparison = {'created_keys': {},
                  'deleted_keys': [],
                  'created_values': {},
                  'deleted_values': {},
                  'modified_values': {}}

    for key, info in registry1.items():
        if key in registry0:
            if info[1] != registry0[key][1]:
                created, deleted, modified = compare_values(
                    registry0[key][1], info[1])

                if created:
                    comparison['created_values'][key] = (info[0], created)
                if deleted:
                    comparison['deleted_values'][key] = (info[0], deleted)
                if modified:
                    comparison['modified_values'][key] = (info[0], modified)
        else:
            comparison['created_keys'][key] = info

    for key in registry0.keys():
        if key not in registry1:
            comparison['deleted_keys'].append(key)

    return comparison


def compare_values(values0, values1):
    """Compares all the values of a single registry key."""
    values0 = {v[0]: v[1:] for v in values0}
    values1 = {v[0]: v[1:] for v in values1}

    created = [(k, v[0], v[1]) for k, v in values1.items() if k not in values0]
    deleted = [(k, v[0], v[1]) for k, v in values0.items() if k not in values1]
    modified = [(k, v[0], v[1]) for k, v in values0.items()
                if v != values1.get(k, None)]

    return created, deleted, modified


def compare_hives(fs0, fs1):
    """Compares all the windows registry hive files
    returning those which differ.

    """
    registries = []

    for path in chain(registries_path(fs0.fsroot), user_registries(fs0, fs1)):
        if fs0.checksum(path) != fs1.checksum(path):
            registries.append(path)

    return registries


def user_registries(fs0, fs1):
    """Returns the list of user registries present on both FileSystems."""
    for user in fs0.ls('{}Users'.format(fs0.fsroot)):
        for path in user_registries_path(fs0.fsroot, user):
            if fs1.exists(path):
                yield path


def files_type(fs0, fs1, files):
    """Inspects the file type of the given files."""
    for file_meta in files['deleted_files']:
        file_meta['type'] = fs0.file(file_meta['path'])
    for file_meta in files['created_files'] + files['modified_files']:
        file_meta['type'] = fs1.file(file_meta['path'])

    return files


def files_size(fs0, fs1, files):
    """Gets the file size of the given files."""
    for file_meta in files['deleted_files']:
        file_meta['size'] = fs0.stat(file_meta['path'])['size']
    for file_meta in files['created_files'] + files['modified_files']:
        file_meta['size'] = fs1.stat(file_meta['path'])['size']

    return files


def visit_filesystem(filesystem):
    """Utility function for running the files iterator at once.

    Returns a dictionary.

        {'/path/on/filesystem': 'file_hash'}

    """
    return dict(filesystem.checksums('/'))


@concurrent.thread
def concurrent_visit_filesystem(filesystem):
    return visit_filesystem(filesystem)


def parse_registries(filesystem, registries):
    """Returns a dictionary with the content of the given registry hives.

    {"\\Registry\\Key\\", (("ValueKey", "ValueType", ValueValue))}

    """
    results = {}

    for path in registries:
        with NamedTemporaryFile(buffering=0) as tempfile:
            filesystem.download(path, tempfile.name)

            registry = RegistryHive(tempfile.name)
            registry.rootkey = registry_root(path)

            results.update({k.path: (k.timestamp, k.values)
                            for k in registry.keys()})

    return results


@concurrent.process(timeout=300)
def concurrent_parse_registries(filesystem, registries):
    return parse_registries(filesystem, registries)


def makedirs(path):
    """Creates the directory tree if non existing."""
    path = Path(path)

    if not path.exists():
        path.mkdir(parents=True)
