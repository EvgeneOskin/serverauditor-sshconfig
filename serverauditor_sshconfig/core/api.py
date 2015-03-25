# coding: utf-8

"""
Copyright (c) 2013 Crystalnix.
License BSD, see LICENSE for more details.
"""

import base64
import json
try:
    import urllib.request as urllib2
except ImportError:
    import urllib2

from .utils import to_bytes, to_str


class API(object):

    API_V1_URL = 'https://serverauditor.com/api/v1/'
    API_V2_URL = 'https://serverauditor.com/api/v2/'

    def get_auth_key(self, username, password):
        """ Returns user's auth token. """

        request = urllib2.Request(self.API_V1_URL + "token/auth/")
        auth_str = '%s:%s' % (username, password)
        auth = base64.encodestring(to_bytes(auth_str)).replace(b'\n', b'')
        request.add_header("Authorization", "Basic %s" % to_str(auth))
        response = urllib2.urlopen(request)
        return json.loads(to_str(response.read()))

    def get_keys_and_connections(self, username, auth_key):
        """ Gets current keys and connections.

        Sends request for getting keys and connections using username and auth_key.
        """

        auth_header = "ApiKey %s:%s" % (username, auth_key)

        request = urllib2.Request(self.API_V1_URL + "terminal/ssh_key/?limit=100")
        request.add_header("Authorization", auth_header)
        request.add_header("Content-Type", "application/json")
        response = urllib2.urlopen(request)
        keys = json.loads(to_str(response.read()))['objects']

        request = urllib2.Request(self.API_V1_URL + "terminal/connection/?limit=100")
        request.add_header("Authorization", auth_header)
        request.add_header("Content-Type", "application/json")
        response = urllib2.urlopen(request)
        connections = json.loads(to_str(response.read()))['objects']

        return keys, connections

    def create_keys_and_connections(self, hosts, username, auth_key):
        """ Creates keys and connections using hosts' configs.

        Sends request for creation keys and connections using username and key.
        """

        auth_header = "ApiKey %s:%s" % (username, auth_key)

        for host in hosts:

            key_numbers = []
            for ssh_key in host['ssh_key']:
                request = urllib2.Request(self.API_V1_URL + "terminal/ssh_key/")
                request.add_header("Authorization", auth_header)
                request.add_header("Content-Type", "application/json")
                response = urllib2.urlopen(request, to_bytes(json.dumps(ssh_key)))
                key_numbers.append(int(response.headers['Location'].rstrip('/').rsplit('/', 1)[-1]))

            key = None
            if key_numbers:
                key = key_numbers[0]

            connection = {
                "hostname": host['hostname'],
                "label": host['host'],
                "ssh_key": key,
                "ssh_password": host['password'],
                "ssh_username": host['user'],
                "port": host['port']
            }
            request = urllib2.Request(self.API_V1_URL + "terminal/connection/")
            request.add_header("Authorization", auth_header)
            request.add_header("Content-Type", "application/json")
            urllib2.urlopen(request, to_bytes(json.dumps(connection)))

        return

    def create_known_hosts(self, known_hosts, username, auth_key):
        """Creates known hosts.

        Sends request for creation known host using username and key.
        """

        auth_header = "ApiKey %s:%s" % (username, auth_key)

        for known_host in known_hosts:
            request = urllib2.Request(self.API_V2_URL + "terminal/knownhost/")
            request.add_header("Authorization", auth_header)
            request.add_header("Content-Type", "application/json")
            urllib2.urlopen(request, to_bytes(json.dumps(known_host)))

        return

    def get_known_hosts(self, username, auth_key):
        """Get known hosts.

        Sends request for getting known host using username and key.
        """

        auth_header = "ApiKey %s:%s" % (username, auth_key)

        request = urllib2.Request(self.API_V2_URL + "terminal/knownhost/")
        request.add_header("Authorization", auth_header)
        request.add_header("Content-Type", "application/json")
        response = urllib2.urlopen(request)
        known_hosts = json.loads(to_str(response.read()))['objects']

        return known_hosts
