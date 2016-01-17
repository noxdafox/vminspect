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
import codecs
from pebble import process
from hivex import Hivex, hive_types
from tempfile import NamedTemporaryFile

from vminspect.filesystem import FileSystem
from vminspect.utils import windows_path, posix_path, registry_path


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


REGISTRY_PATH = ['C:\\Windows\\System32\\config\\SAM',
                 'C:\\Windows\\System32\\config\\SYSTEM',
                 'C:\\Windows\\System32\\config\\DEFAULT',
                 'C:\\Windows\\System32\\config\\SOFTWARE',
                 'C:\\Windows\\System32\\config\\SECURITY']


USER_REGISTRY_PATH = [
    'C:\\Users\\{}\\NTUSER.DAT',
    'C:\\Users\\{}\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat']


def parse_registry(hive, disk=None, filesystem=None):
    """Parses the registry hive's content and returns a dictionary.

        {"RootKey\\Key\\...": (("ValueKey", "ValueType", ValueValue), ... )}

    """
    if disk is not None:
        with FileSystem(disk) as filesystem:
            registry = extract_registry(filesystem, hive)
    elif filesystem is not None:
        registry = extract_registry(filesystem, hive)
    else:
        registry = RegistryHive(hive)

    registry.rootkey = REGISTRY_TYPE.get(os.path.basename(posix_path(hive)), '')

    return dict(registry.keys())


class RegistryHive(Hivex):
    """RegistryHive class.

    Allows to visit a registry hive file given its path.

    This class is a subclass of hivex.Hivex class.

    """
    def __init__(self, filename, verbose=False, debug=False, write=False):
        super().__init__(filename, verbose=False, debug=False, write=False)

        self._rootkey = REGISTRY_TYPE.get(os.path.basename(filename), '')
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

        Yields keys in the form:

            "RootKey\\Key\\...", (("ValueKey", "ValueType", ValueValue), ... )

        """
        for node in self.node_children(self.root()):
            yield from self._visit_registry(node, self._rootkey)

    def _visit_registry(self, node, path):
        path = registry_path(path, self.node_name(node))
        values = (self._parse_value(value) for value in self.node_values(node))

        yield path, tuple(values)

        for child in self.node_children(node):
            yield from self._visit_registry(child, path)

    def _parse_value(self, value):
        vtype = self.value_type(value)[0]
        value_type = VALUE_TYPES.get(vtype, 'UNIDENTIFIED')
        try:
            value_data = self._types_map.get(vtype, self._value_data)(value)
        except RuntimeError:
            value_data = self._value_data(value)

        return self.value_key(value), value_type, str(value_data)

    def _value_data(self, value):
        """Parses binary and unidentified values."""
        return codecs.encode(self.value_value(value)[1], 'base64')


def extract_registry(filesystem, hive):
    """Extracts the registry hive from the given filesystem."""
    with NamedTemporaryFile(buffering=0) as tempfile:
        filesystem.download(posix_path(hive), tempfile.name)

        return RegistryHive(tempfile.name)


def compare_registries(fs0, fs1, concurrent=False):
    hives = compare_hives(fs0, fs1)

    if concurrent:
        task0 = process.concurrent(target=parse_registries, args=(fs0, hives))
        task1 = process.concurrent(target=parse_registries, args=(fs1, hives))

        registry0 = task0.get()
        registry1 = task1.get()
    else:
        registry0 = parse_registries(fs0, hives)
        registry1 = parse_registries(fs1, hives)

    return compare_registry(registry0, registry1)


def compare_registry(registry0, registry1):
    comparison = {'created_keys': {},
                  'deleted_keys': [],
                  'created_values': {},
                  'deleted_values': {},
                  'modified_values': {}}

    for key, values in registry1.items():
        if key in registry0:
            if values != registry0[key]:
                created, deleted, modified = compare_values(registry0[key],
                                                            values)

                if created:
                    comparison['created_values'][key] = created
                if deleted:
                    comparison['deleted_values'][key] = deleted
                if modified:
                    comparison['modified_values'][key] = modified
        else:
            comparison['created_keys'][key] = values

    for key in registry0.keys():
        if key not in registry1:
            comparison['deleted_keys'].append(key)

    return comparison


def compare_values(values0, values1):
    values0 = {v[0]: v[1:] for v in values0}
    values1 = {v[0]: v[1:] for v in values1}

    created = [(k, v[0], v[1]) for k, v in values1.items() if k not in values0]
    deleted = [(k, v[0], v[1]) for k, v in values0.items() if k not in values1]
    modified = [(k, v[0], v[1]) for k, v in values0.items()
                if v != values1.get(k, None)]

    return created, deleted, modified


def compare_hives(fs0, fs1):
    """Returns hives with different sha1s."""
    registries = []

    for path in REGISTRY_PATH + user_registries(fs0, fs1):
        if (fs0.checksum('sha1', posix_path(path)) !=
            fs1.checksum('sha1', posix_path(path))):
            registries.append(path)

    return registries


def user_registries(fs0, fs1):
    """Returns the list of user registries present on both FileSystems."""
    registries = []

    for user in fs0.ls(posix_path('C:\\Users\\')):
        paths = [posix_path(p.format(user)) for p in USER_REGISTRY_PATH]

        for path in paths:
            if fs1.exists(path):
                registries.append(fs1.path(path))

    return registries


def parse_registries(filesystem, registries):
    """Returns a dictionary with the content of the given registry hives.

    {"\\Registry\\Key\\", (("ValueKey", "ValueType", ValueValue))}

    """
    results = {}

    for path in registries:
        results.update(parse_registry(path, filesystem=filesystem))

    return results
