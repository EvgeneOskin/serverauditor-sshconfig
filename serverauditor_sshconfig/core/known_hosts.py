# coding: utf-8

"""
Copyright (c) 2013 Crystalnix.
License BSD, see LICENSE for more details.
"""

import os.path
import re


class KnownHostException(Exception):
    pass


class KnownHosts(object):

    """Representation of known_host file information."""

    USER_FILE_PATH = os.path.expanduser('~/.ssh/known_hosts')
    SYSTEM_FILE_PATH = '/etc/ssh/ssh_known_hosts'

    def __init__(self):
        self._known_hosts = []

    def _is_file_ok(self, path):
        """ Checks that file exists, and user have permissions for read it.

        :param path: path where file is located.
        :return: True or False.
        """

        return os.path.exists(path) and not os.path.isdir(path) and os.access(path, os.R_OK)

    def parse(self):
        def create_file(path):
            """ Creates file. """
            ssh_dir = os.path.dirname(path)
            if not os.path.exists(ssh_dir):
                os.mkdir(ssh_dir, 0o700)

            with open(path, 'w') as f:
                f.write("# File was created by ServerAuditor\n\n")

            return

        for path in (self.USER_FILE_PATH, ):  # self.SYSTEM_CONFIG_PATH):
            if not self._is_file_ok(path):
                create_file(path)
            else:
                with open(path) as f:
                    self._parse_file(f)

        return

    def _parse_file(self, file_object):
        """Parses separated file.

        :raises KnownHostsException: if there is any unparsable line in file.
        :param file_object: file.
        """

        settings_regex = re.compile(
            r'((?P<marker>@(revoked)|(cert-authority))[ \t]+)?'
            r'(?P<hostnames>[^ \t]+)[ \t]+'
            r'(?P<key>[^ \t]+[ \t]+[^ \t]+)'
            r'([ \t]+(?P<comment>.*))?')
        for line in file_object:
            line = line.strip()
            if (line == '') or (line[0] == '#'):
                continue

            match = re.match(settings_regex, line)
            if not match:
                raise KnownHostException("Unparsable line %s" % line)

            known_host = {
                i: match.group(i) or ''
                for i in ('hostnames', 'key', 'marker', 'comment')
            }
            self._known_hosts.append(known_host)

    def get_known_hosts(self):
        return self._known_hosts[:]
