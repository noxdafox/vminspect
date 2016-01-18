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


import json
import logging
import argparse

from vminspect.filesystem import list_files
from vminspect.winreg import parse_registry
from vminspect.comparator import compare_disks


def main():
    results = {}
    arguments = parse_arguments()

    logging.basicConfig(level=arguments.debug and logging.DEBUG or logging.INFO)

    if arguments.name == 'list':
        results = list_files_command(arguments)
    elif arguments.name == 'compare':
        results = compare_command(arguments)
    elif arguments.name == 'registry':
        results = registry_command(arguments)

    print(json.dumps(results, indent=2))


def list_files_command(arguments):
    return list_files(arguments.disk, identify=arguments.identify,
                      size=arguments.size)


def compare_command(arguments):
    return compare_disks(arguments.disk1, arguments.disk2,
                         identify=arguments.identify, size=arguments.size,
                         extract=arguments.extract, path=arguments.path,
                         registry=arguments.registry,
                         concurrent=arguments.concurrent)


def registry_command(arguments):
    return parse_registry(arguments.hive, disk=arguments.disk)


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

    return parser.parse_args()


if __name__ == '__main__':
    main()
