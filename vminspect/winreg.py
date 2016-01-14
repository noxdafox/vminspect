from vminspect.utils import windows_path, posix_path


REGISTRY_VALUE_MAP = {0: 'REG_NONE',
                      1: 'REG_SZ',
                      2: 'REG_EXPAND_SZ',
                      3: 'REG_BINARY',
                      4: 'REG_DWORD',
                      5: 'REG_DWORD_BIG_ENDIAN',
                      6: 'REG_DWORD_LINK',
                      7: 'REG_MULTI_SZ',
                      8: 'REG_RESOURCE_LIST',
                      9: 'REG_FULL_RESOURCE_DESCRIPTOR',
                      10: 'REG_RESOURCE_REQUIREMENTS_LIST',
                      11: 'REG_QWORD'}


REGISTRY_PATH = ('C:\\Windows\\System32\\config\\SAM',
                 'C:\\Windows\\System32\\config\\SYSTEM',
                 'C:\\Windows\\System32\\config\\DEFAULT',
                 'C:\\Windows\\System32\\config\\SOFTWARE',
                 'C:\\Windows\\System32\\config\\SECURITY')


USER_REGISTRY_PATH = (
    'C:\\Users\\.*\\NTUSER.DAT',
    'C:\\Users\\.*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat')


REGISTRY_TYPE = {'DEFAULT': 'HKU',
                 'NTUSER.DAT': 'HKCU',
                 'UsrClass.dat': 'HKCU',
                 'SAM': 'HKLM',
                 'SYSTEM': 'HKLM',
                 'SECURITY': 'HKLM',
                 'SOFTWARE': 'HKLM'}


def registry(filesystem, hive):
    """Iterates over the Windows registry keys contained within
    the given hive path.

        "\\Registry\\Key\\", (("ValueKey", "ValueType", ValueValue))

    Example:

        "\\Classes\\*", (("ViewModel", "REG_SZ", "delta"))

    """
    if filesystem.inspect_get_type(filesystem._root) != 'windows':
        raise RuntimeError('Not a Windows File System')

    filesystem.hivex_open(posix_path(hive))

    try:
        yield from visit_registry(filesystem, filesystem.hivex_root())
    finally:
        filesystem.hivex_close()


def compare_registries(fs0, fs1, concurrent=False):
    registries = compare_hive_files(fs0, fs1)

    if concurrent:
        task0 = process.concurrent(parse_registries, args=(fs0, registries))
        task1 = process.concurrent(parse_registries, args=(fs1, registries))

        registries0 = task0.get()
        registries1 = task1.get()
    else:
        registries0 = parse_registries(fs0, registries)
        registries1 = parse_registries(fs1, registries)


def compare_hive_files(fs0, fs1):
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
        path = posix_path('C:\\Users\\', user)

        if fs1.exists(path):
            registries.append(windows_path(path))

    return registries


def parse_registries(filesystem, registries):
    """Returns a dictionary containing the registries.

    {'HKLM': ("\\Registry\\Key\\", (("ValueKey", "ValueType", ValueValue)))}

    """
    registries = {}

    for path in registries:
        registries[REGISTRY_TYPE[ntpath.basename(path)]] = tuple(
            registry(filesystem, path))

    return registries


def visit_registry(filesystem, node, path=''):
    path = registry_path(path, filesystem.hivex_node_name(node))
    values = (parse_value(filesystem, value)
              for value in filesystem.hivex_node_values(node))

    yield path, tuple(values)

    for child in filesystem.hivex_node_children(node):
        yield from visit_registry(filesystem, child['hivex_node_h'], path=path)


def parse_value(filesystem, value):
    value = value['hivex_value_h']
    value_type = filesystem.hivex_value_type(value)
    value_data = (value_type == 1 and filesystem.hivex_value_utf8(value)
                  or filesystem.hivex_value_value(value))

    return (filesystem.hivex_value_key(value),
            filesystem.VALUE_MAP[value_type],
            value_data)
