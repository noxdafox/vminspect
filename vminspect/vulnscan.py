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
import requests
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor

from vminspect.filesystem import FileSystem


class VulnScanner:
    """Vulnerability scanner.

    Allows to scan the given disk content and query
    a CVE DB for vulnerabilities.

    disk must contain the path of a valid disk image.
    url must be a valid URL to a REST vulnerability service.

    """
    def __init__(self, disk, url):
        self._disk = disk
        self._filesystem = None
        self._url = url.rstrip('/')
        self.logger = logging.getLogger(
            "%s.%s" % (self.__module__, self.__class__.__name__))

    def __enter__(self):
        self._filesystem = FileSystem(self._disk)
        self._filesystem.mount()

        return self

    def __exit__(self, *_):
        self._filesystem.umount()

    def scan(self, concurrency=1):
        """Iterates over the applications installed within the disk
        and queries the CVE DB to determine whether they are vulnerable.

        Concurrency controls the amount of concurrent queries
        against the CVE DB.

        For each vulnerable application the method yields a namedtuple:

        VulnApp(name             -> application name
                version          -> application version
                vulnerabilities) -> list of Vulnerabilities

        Vulnerability(id       -> CVE Id
                      summary) -> brief description of the vulnerability

        """
        self.logger.debug("Scanning FS content.")

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            results = executor.map(self.query_vulnerabilities,
                                   self.applications())

        for report in results:
            application, vulnerabilities = report
            vulnerabilities = list(lookup_vulnerabilities(application.version,
                                                          vulnerabilities))

            if vulnerabilities:
                yield VulnApp(application.name,
                              application.version,
                              vulnerabilities)

    def query_vulnerabilities(self, application):
        name = application.name.lower()
        url = '/'.join((self._url, name, name))

        response = requests.get(url)
        response.raise_for_status()

        return application, response.json()

    def applications(self):
        return (Application(a['app2_name'], a['app2_version'])
                for a in self._filesystem.guestfs.inspect_list_applications2(
                self._filesystem._root))


def lookup_vulnerabilities(app_version, vulnerabilities):
    for vulnerability in vulnerabilities:
        for configuration in vulnerability['vulnerable_configuration']:
            if app_version in configuration:
                yield Vulnerability(vulnerability['id'],
                                    vulnerability['summary'])


VulnApp = namedtuple('VulnApp', ('name',
                                 'version',
                                 'vulnerabilities'))
Application = namedtuple('Application', ('name',
                                         'version'))
Vulnerability = namedtuple('Vulnerability', ('id',
                                             'summary'))
