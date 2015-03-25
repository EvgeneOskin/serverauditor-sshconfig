from serverauditor_sshconfig.core.known_hosts import KnownHosts


def test_parse_file():
    tested = KnownHosts()
    known_hosts = [
        '|1|mL1AvmqzXOldYJWmN1pcvATenwE=|WwsHqahgYgD2Vruq/KwTPr6SF6c='
        ' ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+'
        'PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGE'
        'YsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmv'
        'U31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX'
        '2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6g'
        'bODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ== comment\n',
        'jenkins.rhcloud.com,54.198.176.67'
        ' ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAwUPkUQ84FKIWhOxy5RBBuR9gbrov2ep'
        'ARmFmaxD7NFRayobnDvl8GaBTbH1kxaZ/tYQeIqVE1assL74KArMQBzz6rj0FEWf0zrX'
        'xAY55EGswmWEEdqlYu1LbIxDCG6opqkiq6ocxjea9K3XYq+2aYoAvI3sshSImTYZP1gl'
        'Fhrh3QUsNJHOfDboTLJFNSdLjzXubRMa4eEx7s9pe9kwBOaLNIiVeGzUWg5+KaykSg2U'
        'MB3aG127t8kX+OhDYceVR42ehQJ0MjQGlGoNtldxGrlX8NjxUqvJAo6pqNqRK8Cps7/x'
        '/m0GPXWAgSZymhurXmj1o2LP5nKLtVzMPvwMb0w== comment2\n',
        'jenkins.rhcloud.com'
        ' ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAwUPkUQ84FKIWhOxy5RBBuR9gbrov2ep'
        'ARmFmaxD7NFRayobnDvl8GaBTbH1kxaZ/tYQeIqVE1assL74KArMQBzz6rj0FEWf0zrX'
        'xAY55EGswmWEEdqlYu1LbIxDCG6opqkiq6ocxjea9K3XYq+2aYoAvI3sshSImTYZP1gl'
        'Fhrh3QUsNJHOfDboTLJFNSdLjzXubRMa4eEx7s9pe9kwBOaLNIiVeGzUWg5+KaykSg2U'
        'MB3aG127t8kX+OhDYceVR42ehQJ0MjQGlGoNtldxGrlX8NjxUqvJAo6pqNqRK8Cps7/x'
        '/m0GPXWAgSZymhurXmj1o2LP5nKLtVzMPvwMb0w==\n',
        '@revoked jenkins.rhcloud.com'
        ' ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAwUPkUQ84FKIWhOxy5RBBuR9gbrov2ep'
        'ARmFmaxD7NFRayobnDvl8GaBTbH1kxaZ/tYQeIqVE1assL74KArMQBzz6rj0FEWf0zrX'
        'xAY55EGswmWEEdqlYu1LbIxDCG6opqkiq6ocxjea9K3XYq+2aYoAvI3sshSImTYZP1gl'
        'Fhrh3QUsNJHOfDboTLJFNSdLjzXubRMa4eEx7s9pe9kwBOaLNIiVeGzUWg5+KaykSg2U'
        'MB3aG127t8kX+OhDYceVR42ehQJ0MjQGlGoNtldxGrlX8NjxUqvJAo6pqNqRK8Cps7/x'
        '/m0GPXWAgSZymhurXmj1o2LP5nKLtVzMPvwMb0w== coment\n',
    ]
    tested._parse_file(known_hosts)
    parsed = tested._known_hosts

    assert 3 == len(parsed)
    assert parsed[0]['comment'] == 'comment'
    assert parsed[0]['hostnames'] == '|1|mL1AvmqzXOldYJWmN1pcvATenwE=|WwsHqahgYgD2Vruq/KwTPr6SF6c='
    assert parsed[0]['key'].startswith('ssh-rsa AAAAB3N')
    assert parsed[0]['key'].endswith('bODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==')
    assert parsed[0]['marker'] == ''

    assert parsed[1]['comment'] == 'comment2'
    assert parsed[1]['hostnames'] == 'jenkins.rhcloud.com,54.198.176.67'
    assert parsed[1]['key'].startswith('ssh-rsa AAAAB3NzaC')
    assert parsed[1]['key'].endswith('m0GPXWAgSZymhurXmj1o2LP5nKLtVzMPvwMb0w==')
    assert parsed[1]['marker'] == ''

    assert parsed[2]['comment'] == ''
    assert parsed[2]['hostnames'] == 'jenkins.rhcloud.com,54.198.176.67'
    assert parsed[2]['key'].startswith('ssh-rsa AAAAB3NzaC')
    assert parsed[2]['key'].endswith('m0GPXWAgSZymhurXmj1o2LP5nKLtVzMPvwMb0w==')
    assert parsed[2]['marker'] == ''

    assert parsed[3]['comment'] == 'coment'
    assert parsed[3]['hostnames'] == 'jenkins.rhcloud.com,54.198.176.67'
    assert parsed[3]['key'].startswith('ssh-rsa AAAAB3NzaC')
    assert parsed[3]['key'].endswith('m0GPXWAgSZymhurXmj1o2LP5nKLtVzMPvwMb0w==')
    assert parsed[3]['marker'] == '@revoked'
