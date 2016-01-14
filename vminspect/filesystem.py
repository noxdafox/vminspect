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


import logging
from guestfs import GuestFS
from tempfile import NamedTemporaryFile

from vminspect.utils import windows_path, posix_path, registry_path


def list_files(disk, identify=False, size=False):
    results = []
    logger = logging.getLogger('filesystem')

    with FileSystem(disk) as filesystem:
        logger.debug("Listing files.")

        for path, digest in filesystem.files('/'):
            results.append({'path': path, 'sha1': digest})

        if identify:
            logger.debug("Gatering file types.")
            results = add_file_type(filesystem, results)
        if size:
            logger.debug("Gatering file sizes.")
            results = add_file_size(filesystem, results)

    return results


class FileSystem(GuestFS):
    """Guest FileSystem handler."""
    def __init__(self, disk_path):
        super().__init__()
        self._root = None
        self._os_type = None
        self._disk_path = disk_path

    def __enter__(self):
        self.mount_disk()

        return self

    def __exit__(self, *_):
        self.umount_disk()

    def mount_disk(self, readonly=True):
        """Mounts the given disk.
        It must be called before any other method.

        """
        self.add_drive_opts(self._disk_path, readonly=True)
        self.launch()

        for mountpoint, device in self._inspect_disk():
            if readonly:
                self.mount_ro(device, mountpoint)
            else:
                self.mount(device, mountpoint)

        if self.inspect_get_type(self._root) == 'windows':
            self._path = self._windows_path
        else:
            self._path = self._posix_path

    def _inspect_disk(self):
        """Inspects the disk and returns the mountpoints mapping
        as a list which order is the supposed one for correct mounting.

        """
        roots = self.inspect_os()

        if roots:
            self._root = roots[0]
            return sorted(self.inspect_get_mountpoints(self._root),
                          key=lambda m: len(m[0]))
        else:
            raise RuntimeError("No OS found on the given disk image.")

    def umount_disk(self):
        """Unmounts the disk.

        After this method is called no further action is allowed.

        """
        self.close()

    def visit(self, path):
        """Iterates over the files and directories contained within the disk
        starting from the given path.

        """
        path = posix_path(path)

        yield from (self._path(path, e) for e in super().find(path))

    def files(self, path, hashtype='sha1'):
        """Iterates over the files contained within the disk starting from
        the given path.

        The hashtype keyword allows to choose the file hashing algorithm.

        Yields the following values:

            "C:\\Windows\\System32\\NTUSER.DAT", "hash" for windows
            "/home/user/text.txt", "hash" for other FS

        """
        with NamedTemporaryFile(buffering=0) as tempfile:
            self.checksums_out(hashtype, posix_path(path), tempfile.name)

            yield from ((self._path(f[1].lstrip('.')), f[0])
                        for f in (l.decode('utf8').strip().split(None, 1)
                                  for l in tempfile))

    def _path(self, *segments):
        raise NotImplementedError("FileSystem needs to be mounted first")

    def _posix_path(self, *segments):
        return posix_path(*segments)

    def _windows_path(self, *segments):
        drive = self.inspect_get_drive_mappings(self._root)[0][0]

        return windows_path(drive, *segments)


def add_file_type(filesystem, files):
    """Inspects the file type of the given files."""
    for file_meta in files:
        file_meta['type'] = filesystem.file(posix_path(file_meta['path']))

    return files


def add_file_size(filesystem, files):
    """Gets the file size of the given files."""
    for file_meta in files:
        file_meta['size'] = filesystem.stat(
            posix_path(file_meta['path']))['size']

    return files
