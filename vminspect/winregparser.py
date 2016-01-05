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


# TODO: test
"""Not tested yet"""


import re
import sys
import json
import ntpath
from lxml import etree
from tempfile import NamedTemporaryFile
from collections import namedtuple, defaultdict

from .utils import launch_process, process_output


HIVEXML = 'hivexml'


RegistryKey = namedtuple('RegistryKey', ('name', 'children', 'values'))
RegistryValue = namedtuple('RegistryValue', ('name', 'type', 'data'))


REGISTRY_TYPE = {'DEFAULT': 'HKU',
                 'NTUSER.DAT': 'HKCU',
                 'UsrClass.dat': 'HKCU',
                 'SAM': 'HKLM',
                 'SYSTEM': 'HKLM',
                 'SECURITY': 'HKLM',
                 'SOFTWARE': 'HKLM'}


REGISTRY_PATH = ('Users\\\\.*\\\\NTUSER.DAT$',
                 'AppData\\\\Local\\\\Microsoft\\\\Windows\\\\UsrClass.dat$',
                 'Windows\\\\System32\\\\config\\\\SAM$',
                 'Windows\\\\System32\\\\config\\\\SYSTEM$',
                 'Windows\\\\System32\\\\config\\\\DEFAULT$',
                 'Windows\\\\System32\\\\config\\\\SOFTWARE$',
                 '\\\\Windows\\\\System32\\\\config\\\\SECURITY$')


VALUE_TYPES = {'string': 'REG_SZ',
               'string-list': 'REG_MULTI_SZ',
               'int32': 'REG_DWORD',
               'none': 'REG_NONE',
               'binary': 'REG_BINARY',
               'int64': 'REG_QWORD',
               'expand': 'REG_EXPAND_SZ'}


def registry_type(registry_path):
    """Given a registry path, returns its type."""
    return REGISTRY_TYPE[ntpath.basename(registry_path)]


def registry_files(files, path_getter=None):
    """Given a list of files, returns those belonging to a registry hive.

    files must be a list of file path in Windows format. If given,
    path_getter will be called for each file to retrieve its path.

    """
    files = []
    pattern = '|'.join(REGISTRY_PATH)
    path_getter = path_getter is None and str or path_getter

    for candidate in files:
        if re.search(pattern, path_getter(candidate)) is not None:
            files.append(candidate)

    return files


def compare_registry_hives(old_hive_path, new_hive_path):
    """Compares two registry hive files and returns their differences."""
    xml_files = []
    registry_types = (registry_type(old_hive_path),
                      registry_type(new_hive_path))
    hive_processes = (launch_process([HIVEXML, old_hive_path]),
                      launch_process([HIVEXML, new_hive_path]))

    for process in hive_processes:
        hive_xml = NamedTemporaryFile()
        xml_files.append(hive_xml)

        process_output(process, hive_xml.name)

    return compare_registry(xml_files[0].name, xml_files[1].name,
                            registry_types)


def compare_registry(old_hive_xml, new_hive_xml, registry_types):
    registry_keys = []
    results = defaultdict(list)

    old_hive = parse_registry(old_hive_xml, registry_types[0])
    new_hive = parse_registry(new_hive_xml, registry_types[1])

    for key, values in new_hive.items():
        if key in old_hive:
            if values != old_hive[key]:
                values = compare_values(key, old_hive[key], values)

                for result_key, result_list in values.items():
                    results[result_key].extend(result_list)
        else:
            results['created_keys'].append(
                {'key': key,
                 'values': [{'type': v.type,
                             'name': v.name,
                             'value': v.data}
                            for v in values.values()]})

    for key, values in old_hive.items():
        if key not in new_hive:
            results['deleted_keys'].append(key)

    return results


def parse_registry(hive_xml, registry_type):
    """Parses the registry XML file returning a dictionary."""
    registry_root = parse_windows_registry(hive_xml, registry_type)

    return registry_dictionary(registry_root)


def compare_values(key, old_values, new_values):
    results = defaultdict(list)

    for name, value in new_values.items():
        if name in old_values:
            if value != old_values[name]:
                results['modified_values'].append({'key': key,
                                                   'name': name,
                                                   'original_value': old_values[name].data,
                                                   'value': value.data,
                                                   'type': value.type})
        else:
            results['new_values'].append({'key': key,
                                          'name': name,
                                          'value': value.data,
                                          'type': value.type})
    for name, value in old_values.items():
        if name not in new_values:
            results['deleted_values'].append({'key': key,
                                              'name': name,
                                              'original_value': value.data,
                                              'type': value.type})

    return results


def parse_windows_registry(xml_path, registry_type):
    context = etree.iterparse(xml_path, events=('start', 'end'), tag='node',
                              recover=True)
    tree = parse_tree(context, RegistryKey('root', [], []))
    root = tree.children[0]

    return RegistryKey(registry_type, root.children, root.values)


def registry_dictionary(registry_root):
    registry_keys = defaultdict(dict)

    for key, value in visit_tree(registry_root):
        registry_keys[key][value.name] = value

    return registry_keys


def parse_tree(context, root_key):
    """Recursively parses the XML building the hive tree."""
    current_key = None

    for event, element in context:
        name = element.attrib['name']
        values = parse_values(element)

        if event == 'start':
            if current_key is not None:
                child_key = parse_tree(context, RegistryKey(name, [], values))
                current_key.children.append(child_key)
            else:
                current_key = RegistryKey(name, [], values)
        else:
            if current_key is not None:
                root_key.children.append(current_key)
                current_key = None
            else:
                return root_key

    return root_key


def parse_values(key):
    """Extracts all the values of a given key."""
    values = []

    for _, value_element in etree.iterwalk(key, tag='value'):
        value = value_factory(value_element)
        values.append(value)

    return values


def value_factory(element):
    """Returns a RegistryValue object from the XML element."""
    value_name = element.attrib.get('key', 'Default')
    value_type = VALUE_TYPES.get(element.attrib['type'], 'UNKNOWN')

    if value_type == 'REG_MULTI_SZ':
        elements = [s for _, s in etree.iterwalk(element, tag='string')]
        value_data = '; '.join([e.text or '' for e in elements])
    else:
        value_data = element.attrib.get('value', '')

    return RegistryValue(value_name, value_type, value_data)


def visit_tree(root_key, path=""):
    """Iterates over the hive tree from the given root key.

    Yields a tuple (path\\RegistryKey, value).

    """
    for key in root_key.children:
        for value in key.values:
            yield "%s\\%s\\%s" % (path, root_key.name, key.name), value

        if key.children:
            for key, value in visit_tree(key,
                                         path="%s\\%s" % (path, root_key.name)):
                yield key, value


def main():
    results = compare_registry_hives(sys.argv[1], sys.argv[2], sys.argv[3])
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
