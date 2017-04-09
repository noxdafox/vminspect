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


import re
import time
import logging
import requests
from collections import namedtuple
from itertools import chain, islice

from vminspect.filesystem import FileSystem


VTReport = namedtuple('VTReport', ('path', 'hash', 'detections'))


class VTScanner:
    """VirusTotal scanner.

    Allows to scan the given disk content and query VirusTotal.

    disk must contain the path of a valid disk image.
    apikey must be a valid VT API key.

    The attribute batchsize controls the amount of object per VT query.

    """
    def __init__(self, disk, apikey):
        self._disk = disk
        self._apikey = apikey
        self._filesystem = None
        self.batchsize = 1
        self.logger = logging.getLogger(
            "%s.%s" % (self.__module__, self.__class__.__name__))

    def __enter__(self):
        self._filesystem = FileSystem(self._disk)
        self._filesystem.mount()

        return self

    def __exit__(self, *_):
        self._filesystem.umount()

    def __getattr__(self, attr):
        return getattr(self._filesystem, attr)

    @property
    def apikey(self):
        return self._apikey

    def scan(self, filetypes=None):
        """Iterates over the content of the disk and queries VirusTotal
        to determine whether it's malicious or not.

        filetypes is a list containing regular expression patterns.
        If given, only the files which type will match with one or more of
        the given patterns will be queried against VirusTotal.

        For each file which is unknown by VT or positive to any of its engines,
        the method yields a namedtuple:

        VTReport(path        -> C:\\Windows\\System32\\infected.dll
                 hash        -> ab231...
                 detections) -> dictionary engine -> detection

        Files unknown by VirusTotal will contain the string 'unknown'
        in the detection field.

        """
        self.logger.debug("Scanning FS content.")
        checksums = self.filetype_filter(self._filesystem.checksums('/'),
                                         filetypes=filetypes)

        self.logger.debug("Querying %d objects to VTotal.", len(checksums))

        for files in chunks(checksums, size=self.batchsize):
            files = dict((reversed(e) for e in files))
            response = vtquery(self._apikey, files.keys())

            yield from self.parse_response(files, response)

    def filetype_filter(self, files, filetypes=None):
        if filetypes is not None:
            return [f for f in files
                    if any((re.match(t, self._filesystem.file(f[0]))
                            for t in filetypes))]
        else:
            return files

    def parse_response(self, files, response):
        response = isinstance(response, list) and response or [response]

        for result in response:
            yield from self.parse_result(result, files)

    def parse_result(self, result, files):
        sha1 = result['resource']
        path = files[sha1]

        if result['response_code'] > 0:
            positives = result['positives']

            self.logger.debug("%s - %d positives.", path, positives)

            if positives > 0:
                detections = {engine: detection for engine, detection
                              in result['scans'].items()
                              if detection['detected']}

                yield VTReport(path, sha1, detections)
        else:
            self.logger.debug("%s - Unknown file.", path)

            yield VTReport(path, sha1, 'UNKNOWN')


def vtquery(apikey, checksums):
    """Performs the query dealing with errors and throttling requests."""
    data = {'apikey': apikey,
            'resource': isinstance(checksums, str) and checksums
                        or ', '.join(checksums)}

    while 1:
        response = requests.post(VT_REPORT_URL, data=data)
        response.raise_for_status()

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 204:
            logging.debug("API key request rate limit reached, throttling.")
            time.sleep(VT_THROTTLE)
        else:
            raise RuntimeError("Response status code %s" % response.status_code)


def chunks(iterable, size=1):
    """Splits iterator in chunks."""
    iterator = iter(iterable)

    for element in iterator:
        yield chain([element], islice(iterator, size - 1))


VT_THROTTLE = 60
VT_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
