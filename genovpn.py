#!/usr/bin/env python3
from os import getenv
from sys import argv
from pathlib import Path

SERVER = 'servername'
SERVER_PATH = Path('/etc/openvpn/server')
PORT = 1197
PROTO = 'udp'
EASYRSA_PATH = Path('/etc/easy-rsa')
conf = """
client
remote {server} {port} {proto}
dev tun
cipher AES-256-CBC
auth SHA512
comp-lzo


<tls-auth>
{tls_auth}
</tls-auth>


# Additional Config
resolv-retry infinite
nobind
persist-key
persist-tun
verb 3
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-256-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA:TLS-DHE-RSA-WITH-AES-128-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA  # noqa
remote-cert-tls server
key-direction 1


<ca>
{ca}
</ca>


<cert>
{cert}
</cert>


<key>
{key}
</key>
"""


def main():
    global EASYRSA_PATH, conf
    EASYRSA_PATH = getenv('EASYRSA') or EASYRSA_PATH
    if 2 != len(argv):
        print('Usage: {} clientname'.format(argv[0]))
        exit(1)

    _, clientname = argv
    files = {
        'ca': SERVER_PATH / 'ca.crt',
        'cert': EASYRSA_PATH / 'pki' / 'issued' / (clientname + '.crt'),
        'key': EASYRSA_PATH / 'pki' / 'private' / (clientname + '.key'),
        'tls-auth': SERVER_PATH / 'ta.key',
    }

    nonexistent = []
    unreadable = []
    for f in files.values():
        if not f.exists():
            nonexistent.append(f)
    for f in set(files.values()) - set(nonexistent):
        try:
            with f.open('r'):
                pass
        except PermissionError:
            unreadable.append(f)
    if nonexistent:
        print('These files do not exist:')
        for f in nonexistent:
            print('    {}'.format(f))
        print()
    if unreadable:
        print(
            'These files were unable to open, '
            'try with administrative permissions:'
        )
        for f in unreadable:
            print('    {}'.format(f))
    if nonexistent or unreadable:
        exit(1)

    contents = {}
    for d, f in files.items():
        with f.open('r') as r:
            contents[d] = r.read()

    conf = conf.strip().format(
        server=SERVER,
        port=PORT,
        proto=PROTO,
        tls_auth=contents['tls-auth'].strip(),
        ca=contents['ca'].strip(),
        cert=contents['cert'].strip(),
        key=contents['key'].strip(),
    )

    try:
        with Path(SERVER + '-' + clientname + '.ovpn').open('w') as w:
            w.write(conf)
    except PermissionError:
        print(
            'Could not write to {}, try again with elevated rights'.format(
                Path(clientname + '.ovpn').resolve()
            )
        )
        exit(1)


if __name__ == '__main__':
    main()
