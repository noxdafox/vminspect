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


import os
import json
import shutil
import hashlib
import logging
import argparse
from tempfile import NamedTemporaryFile

from vminspect.vtscan import VTScanner
from vminspect.usnjrnl import usn_journal
from vminspect.vulnscan import VulnScanner
from vminspect.timeline import NTFSTimeline
from vminspect.filesystem import FileSystem
from vminspect.comparator import DiskComparator
from vminspect.winreg import RegistryHive, registry_root


def main():
    results = {}
    arguments = parse_arguments()

    logging.basicConfig(level=arguments.debug and logging.DEBUG or logging.INFO)
    logging.getLogger('requests').setLevel(logging.WARNING)

    if arguments.name == 'list':
        results = list_files_command(arguments)
    elif arguments.name == 'compare':
        results = compare_command(arguments)
    elif arguments.name == 'registry':
        results = registry_command(arguments)
    elif arguments.name == 'vtscan':
        results = vtscan_command(arguments)
    elif arguments.name == 'vulnscan':
        results = vulnscan_command(arguments)
    elif arguments.name == 'usnjrnl':
        results = usnjrnl_command(arguments)
    elif arguments.name == 'timeline':
        results = timeline_command(arguments)

    print(json.dumps(results, indent=2))


def list_files_command(arguments):
    return list_files(arguments.disk, identify=arguments.identify,
                      size=arguments.size)


def list_files(disk, identify=False, size=False):
    logger = logging.getLogger('filesystem')

    with FileSystem(disk) as filesystem:
        logger.debug("Listing files.")
        files = [{'path': path, 'sha1': digest}
                 for path, digest in filesystem.checksums('/')]

        if identify:
            logger.debug("Gatering file types.")
            for file_meta in files:
                file_meta['type'] = filesystem.file(file_meta['path'])

        if size:
            logger.debug("Gatering file sizes.")
            for file_meta in files:
                file_meta['size'] = filesystem.stat(file_meta['path'])['size']

    return files


def compare_command(arguments):
    return compare_disks(arguments.disk1, arguments.disk2,
                         identify=arguments.identify, size=arguments.size,
                         extract=arguments.extract, path=arguments.path,
                         registry=arguments.registry,
                         concurrent=arguments.concurrent)


def compare_disks(disk1, disk2, identify=False, size=False, registry=False,
                  extract=False, path='.', concurrent=False):
    with DiskComparator(disk1, disk2) as comparator:
        results = comparator.compare(concurrent=concurrent,
                                     identify=identify,
                                     size=size)
        if extract:
            extract = results['created_files'] + results['modified_files']
            files = comparator.extract(1, extract, path=path)

            results.update(files)

        if registry:
            registry = comparator.compare_registry(concurrent=concurrent)

            results['registry'] = registry

    return results


def registry_command(arguments):
    return parse_registry(arguments.hive, disk=arguments.disk)


def parse_registry(hive, disk=None):
    """Parses the registry hive's content and returns a dictionary.

        {"RootKey\\Key\\...": (("ValueKey", "ValueType", ValueValue), ... )}

    """
    if disk is not None:
        with FileSystem(disk) as filesystem:
            registry = extract_registry(filesystem, hive)
    else:
        registry = RegistryHive(hive)

    registry.rootkey = registry_root(hive)

    return dict(registry.keys())


def extract_registry(filesystem, path):
    with NamedTemporaryFile(buffering=0) as tempfile:
        filesystem.download(path, tempfile.name)

        return RegistryHive(tempfile.name)


def vtscan_command(arguments):
    with VTScanner(arguments.disk, arguments.apikey) as vtscanner:
        vtscanner.batchsize = arguments.batchsize
        filetypes = arguments.types and arguments.types.split(',') or None

        return [r._asdict() for r in vtscanner.scan(filetypes=filetypes)]


def vulnscan_command(arguments):
    with VulnScanner(arguments.disk, arguments.url) as vulnscanner:
        return [r._asdict() for r in vulnscanner.scan(arguments.concurrency)]


def usnjrnl_command(arguments):
    return parse_usnjrnl(arguments.usnjrnl, disk=arguments.disk)


def parse_usnjrnl(usnjrnl, disk=None):
    if disk is not None:
        with FileSystem(disk) as filesystem:
            return extract_usnjrnl(filesystem, usnjrnl)
    else:
        return [e._asdict() for e in usn_journal(usnjrnl)]


def extract_usnjrnl(filesystem, path):
    with NamedTemporaryFile(buffering=0) as tempfile:
        root = filesystem.guestfs.inspect_get_roots()[0]
        inode = filesystem.stat(path)['ino']
        filesystem.guestfs.download_inode(root, inode, tempfile.name)

        return [e._asdict() for e in usn_journal(tempfile.name)]


def timeline_command(arguments):
    logger = logging.getLogger('timeline')

    with NTFSTimeline(arguments.disk) as timeline:
        events = [e._asdict() for e in timeline.timeline()]

        if arguments.identify:
            logger.debug("Gatering file types.")
            events = identify_files(timeline, events)

        if arguments.hash:
            logger.debug("Gatering file hashes.")
            events = calculate_hashes(timeline, events)

        if arguments.extract:
            logger.debug("Extracting created files.")
            extract_created_files(timeline, arguments.extract, events)

        if arguments.recover:
            logger.debug("Recovering deleted files.")
            extract_deleted_files(timeline, arguments.recover, events)

    return events


def identify_files(timeline, events):
    for event in (e for e in events if e['allocated']):
        try:
            event['type'] = timeline.file(event['path'])
        except RuntimeError:
            pass

    return events


def calculate_hashes(timeline, events):
    for event in (e for e in events if e['allocated']):
        try:
            event['hash'] = timeline.checksum(event['path'])
        except RuntimeError:
            pass

    return events


def extract_created_files(timeline, path, events):
    for event in (e for e in events
                  if 'FILE_CREATE' in e['changes'] and e['allocated']):
        try:
            if 'hash' in event:
                sha_hash = event['hash']
            else:
                sha_hash = timeline.checksum(event['path'])
            source = event['path']
            destination = os.path.join(path, sha_hash)

            if not os.path.exists(destination):
                timeline.download(source, destination)
        except RuntimeError:
            pass


def extract_deleted_files(timeline, path, events):
    root = timeline.guestfs.inspect_get_roots()[0]

    for event in (e for e in events if 'FILE_DELETE' in e['changes']):
        inode = event['file_reference_number']

        try:
            with NamedTemporaryFile(buffering=0) as tempfile:
                timeline.guestfs.download_inode(root, inode, tempfile.name)

                event['recovered'] = True
                event['hash'] = hashlib.sha1(tempfile.read()).hexdigest()
                destination = os.path.join(path, event['hash'])

                shutil.copy(tempfile.name, destination)
        except RuntimeError:
            event['recovered'] = False


def parse_arguments():
    parser = argparse.ArgumentParser(description='Inspects VM disk images.')
    parser.add_argument('-d', '--debug', action='store_true', default=False,
                        help='log in debug mode')

    subparsers = parser.add_subparsers(dest='name', title='subcommands',
                                       description='valid subcommands')

    list_parser = subparsers.add_parser('list',
                                        help='Lists the content of a disk.')
    list_parser.add_argument('disk', type=str, help='path to disk image')
    list_parser.add_argument('-i', '--identify', action='store_true',
                             default=False, help='report file types')
    list_parser.add_argument('-s', '--size', action='store_true',
                             default=False, help='report file sizes')

    compare_parser = subparsers.add_parser('compare',
                                           help='Compares two disks.')
    compare_parser.add_argument('disk1', type=str,
                                help='path to first disk image')
    compare_parser.add_argument('disk2', type=str,
                                help='path to second disk image')
    compare_parser.add_argument('-c', '--concurrent', action='store_true',
                                default=False, help='use concurrency')
    compare_parser.add_argument('-e', '--extract', action='store_true',
                                default=False, help='extract new files')
    compare_parser.add_argument('-p', '--path', type=str, default='.',
                                help='path where to extract files')
    compare_parser.add_argument('-i', '--identify', action='store_true',
                                default=False, help='report file types')
    compare_parser.add_argument('-s', '--size', action='store_true',
                                default=False, help='report file sizes')
    compare_parser.add_argument('-r', '--registry', action='store_true',
                                default=False, help='compare registry')

    registry_parser = subparsers.add_parser(
        'registry', help='Lists the content of a registry file.')
    registry_parser.add_argument('hive', type=str, help='path to hive file')
    registry_parser.add_argument('-d', '--disk', type=str, default=None,
                                 help='path to disk image')

    vtscan_parser = subparsers.add_parser(
        'vtscan', help='Scans a disk and queries VirusTotal.')
    vtscan_parser.add_argument('apikey', type=str, help='VirusTotal API key')
    vtscan_parser.add_argument('disk', type=str, help='path to disk image')
    vtscan_parser.add_argument('-b', '--batchsize', type=int, default=1,
                               help='VT requests batch size')
    vtscan_parser.add_argument(
        '-t', '--types', type=str, default='',
        help='comma separated list of file types (REGEX) to be scanned')

    vulnscan_parser = subparsers.add_parser(
        'vulnscan', help='Scans a disk and queries VBE.')
    vulnscan_parser.add_argument('url', type=str,
                                 help='URL to vulnerabilities DB')
    vulnscan_parser.add_argument('disk', type=str, help='path to disk image')
    vulnscan_parser.add_argument('-c', '--concurrency', type=int, default=1,
                                 help='amount of concurrent queries against DB')

    usnjrnl_parser = subparsers.add_parser(
        'usnjrnl', help='Parses the Update Sequence Number Journal file.')
    usnjrnl_parser.add_argument('usnjrnl', type=str, help='path to USN file')
    usnjrnl_parser.add_argument('-d', '--disk', type=str, default=None,
                                help='path to disk image')

    timeline_parser = subparsers.add_parser(
        'timeline', help='Builds the event timeline of an NTFS disk.')
    timeline_parser.add_argument('disk', type=str, help='path to disk image')
    timeline_parser.add_argument('-i', '--identify', action='store_true',
                                 default=False, help='report file types')
    timeline_parser.add_argument('-s', '--hash', action='store_true',
                                 default=False, help='report file hash (SHA1)')
    timeline_parser.add_argument('-e', '--extract', type=str, default='',
                                 help='Extract created files into path')
    timeline_parser.add_argument('-r', '--recover', type=str, default='',
                                 help='Try recovering deleted files')

    return parser.parse_args()


if __name__ == '__main__':
    main()
