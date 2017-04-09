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


"""Module for parsing Windows Registry hive files."""


import ntpath
import codecs
from collections import namedtuple
from datetime import datetime, timedelta

try:
    from hivex import Hivex, hive_types
except ImportError:
    from hivex import Hivex

    class hive_types:
        REG_NONE = 0
        REG_SZ = 1
        REG_EXPAND_SZ = 2
        REG_BINARY = 3
        REG_DWORD = 4
        REG_DWORD_BIG_ENDIAN = 5
        REG_LINK = 6
        REG_MULTI_SZ = 7
        REG_RESOURCE_LIST = 8
        REG_FULL_RESOURCE_DESCRIPTOR = 9
        REG_RESOURCE_REQUIREMENTS_LIST = 10
        REG_QWORD = 11


class RegistryHive(Hivex):
    """RegistryHive class.

    Allows to visit a registry hive file given its path.

    This class is a subclass of hivex.Hivex class.

    """
    def __init__(self, filename, verbose=False, debug=False, write=False):
        super().__init__(filename, verbose=False, debug=False, write=False)

        self._rootkey = registry_root(filename)
        self._types_map = {hive_types.REG_SZ: self.value_string,
                           hive_types.REG_EXPAND_SZ: self.value_string,
                           hive_types.REG_LINK: self.value_string,
                           hive_types.REG_MULTI_SZ: self.value_multiple_strings,
                           hive_types.REG_DWORD: self.value_dword,
                           hive_types.REG_DWORD_BIG_ENDIAN: self.value_dword,
                           hive_types.REG_QWORD: self.value_qword}

    @property
    def rootkey(self):
        """Returns the Registry Root Key."""
        return self._rootkey

    @rootkey.setter
    def rootkey(self, key):
        """Sets the Registry Root Key."""
        self._rootkey = key

    def keys(self):
        """Iterates over the hive's keys.

        Yields WinRegKey namedtuples containing:

            path: path of the key "RootKey\\Key\\..."
            timestamp: date and time of last modification
            values: list of values (("ValueKey", "ValueType", ValueValue), ... )

        """
        for node in self.node_children(self.root()):
            yield from self._visit_registry(node, self._rootkey)

    def _visit_registry(self, node, path):
        path = ntpath.join(path, self.node_name(node))
        values = (self._parse_value(value) for value in self.node_values(node))
        timestamp = (datetime(1601, 1, 1) + timedelta(
            microseconds=(self.node_timestamp(node) / 10))).isoformat(' ')

        yield WinRegKey(path, timestamp, tuple(values))

        for child in self.node_children(node):
            yield from self._visit_registry(child, path)

    def _parse_value(self, value):
        vtype = self.value_type(value)[0]
        value_type = VALUE_TYPES.get(vtype, 'UNIDENTIFIED')
        try:
            value_data = self._types_map.get(vtype, self._value_data)(value)
        except RuntimeError:
            value_data = self._value_data(value)

        return self.value_key(value), value_type, value_data

    def _value_data(self, value):
        """Parses binary and unidentified values."""
        return codecs.decode(
            codecs.encode(self.value_value(value)[1], 'base64'), 'utf8')


def registry_root(path):
    """Guesses the registry root from the file name."""
    return REGISTRY_TYPE.get(ntpath.basename(path), '')


def registries_path(fsroot):
    """Iterates over the registry hives locations.

    fsroot must contain the file system root, ex: C:\\

    """
    return (p.format(fsroot) for p in REGISTRY_PATH)


def user_registries_path(fsroot, user):
    """Iterates over the user registry hives locations.

    fsroot must contain the file system root, ex: C:\\

    """
    return (p.format(fsroot, user) for p in USER_REGISTRY_PATH)


WinRegKey = namedtuple('WinRegKey', ('path', 'timestamp', 'values'))


VALUE_TYPES = {
    hive_types.REG_NONE: 'REG_NONE',
    hive_types.REG_SZ: 'REG_SZ',
    hive_types.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
    hive_types.REG_BINARY: 'REG_BINARY',
    hive_types.REG_DWORD: 'REG_DWORD',
    hive_types.REG_DWORD_BIG_ENDIAN: 'REG_DWORD_BIG_ENDIAN',
    hive_types.REG_LINK: 'REG_LINK',
    hive_types.REG_MULTI_SZ: 'REG_MULTI_SZ',
    hive_types.REG_RESOURCE_LIST: 'REG_RESOURCE_LIST',
    hive_types.REG_FULL_RESOURCE_DESCRIPTOR: 'REG_FULL_RESOURCE_DESCRIPTOR',
    hive_types.REG_RESOURCE_REQUIREMENTS_LIST: 'REG_RESOURCE_REQUIREMENTS_LIST',
    hive_types.REG_QWORD: 'REG_QWORD'}


REGISTRY_TYPE = {'DEFAULT': 'HKU',
                 'NTUSER.DAT': 'HKCU',
                 'UsrClass.dat': 'HKCU',
                 'SAM': 'HKLM',
                 'SYSTEM': 'HKLM',
                 'SECURITY': 'HKLM',
                 'SOFTWARE': 'HKLM'}


REGISTRY_PATH = ['{}Windows\\System32\\config\\SAM',
                 '{}Windows\\System32\\config\\SYSTEM',
                 '{}Windows\\System32\\config\\DEFAULT',
                 '{}Windows\\System32\\config\\SOFTWARE',
                 '{}Windows\\System32\\config\\SECURITY']


USER_REGISTRY_PATH = [
    '{}Users\\{}\\NTUSER.DAT',
    '{}Users\\{}\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat']
