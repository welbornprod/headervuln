#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" headervuln.py
    Like 'gethead.py', checks for vulnerable header settings on servers.
    Inspiration: https://github.com/httphacker
    -Christopher Welborn 12-31-2015
"""

import os
import sys
from urllib import request

from colr import auto_disable as colr_auto_disable, Colr as C
from docopt import docopt

colr_auto_disable()

NAME = 'Header Vulnerability Checker'
VERSION = '0.0.2'
VERSIONSTR = '{} v. {}'.format(NAME, VERSION)
SCRIPT = os.path.split(os.path.abspath(sys.argv[0]))[1]
SCRIPTDIR = os.path.abspath(sys.path[0])

USAGESTR = """{versionstr}
    Usage:
        {script} -h | -v
        {script} URL

    Options:
        URL           : URL to check. Protocol must be specified, otherwise
                        http:// is used.
        -h,--help     : Show this help message.
        -v,--version  : Show version.
""".format(script=SCRIPT, versionstr=VERSIONSTR)


class AnyValue(object):
    """ Signifies any setting is acceptable.
        if HEADERS[name]['accepted'] is ANY and responseheaders.get(name).
    """

    def __str__(self):
        return '<any value>'
ANY = AnyValue()

HEADERS = {
    'x-xss-protection': {
        'accepted': ('1; mode=block',),
        'verbose': 'Cross-Site Scripting',
    },
    'x-frame-options': {
        'accepted': ('deny', 'sameorigin'),
        'verbose': 'Cross-Frame Scripting',
    },
    'x-content-type-options': {
        'accepted': ('nosniff',),
        'verbose': 'MIME-Sniffing',
    },
    'strict-transport-security': {
        'accepted': ANY,
        'verbose': 'HTTP over TLS/SSL',
    },
    'content-security-policy': {
        'accepted': ANY,
        'verbose': 'Content Security Policy',
    },
    'access-control-allow-origin': {
        'accepted': ANY,
        'verbose': 'Access Control Policy',
    },
    'x-download-options': {
        'accepted': ('noopen', ),
        'verbose': 'File Download and Open Restriction Policy',
    },
    'cache-control': {
        'accepted': ANY,
        'verbose': 'Content Caching Policy',
    },
}

MAX_HEADER_LEN = len(max(HEADERS, key=len))
MAX_VERBOSE_LEN = len(
    HEADERS[max(HEADERS, key=lambda k: len(HEADERS[k]['verbose']))]['verbose']
)


def main(argd):
    """ Main entry point, expects doctopt arg dict as argd. """
    try:
        headers = get_headers(argd['URL'])
    except OSError as ex:
        print_err('Unable to get headers: {}\n{}'.format(argd['URL'], ex))
        return 1

    errs = 0
    for headername in HEADERS:
        success = check_header(headername, headers)
        if not success:
            errs += 1
        print(
            format_header_check(
                headername,
                enforced=success,
                value=headers.get(headername, None)
            ))
    if errs:
        plural = 'vulnerability' if errs == 1 else 'vulnerabilities'
        print_err('\nFound {} {}.'.format(errs, plural))
    else:
        print(C('\nAll clear.', 'green'))
    return errs


def check_header(name, headers):
    """ Check a single header value with the vulnerability map. """
    val = headers.get(name, None)
    if not val:
        # No header value set.
        return False
    # Value is set.
    return (
        (HEADERS[name]['accepted'] is ANY) or
        (val.lower() in HEADERS[name]['accepted'])
    )


def format_accepted_values(headername):
    """ Return a comma-separated list of acceptable values for a header,
        or the 'any' string if it was used.
    """
    if HEADERS[headername]['accepted'] is ANY:
        return C(ANY, 'yellow')
    return C(', ').join(
        C(val, 'yellow') for val in HEADERS[headername]['accepted']
    )


def format_header_check(headername, enforced=True, value=None):
    """ Return a formatted message for an acceptable header value. """
    msg = C('enforced', 'green') if enforced else C('not enforced', 'red')
    return str(C('\n    ').join(
        C(headername, 'blue'),
        C(' : ').join(
            C(HEADERS[headername]['verbose'].ljust(MAX_VERBOSE_LEN), 'cyan'),
            msg.ljust(12)
        ),
        C(': ').join(
            C('Expecting', 'cyan'),
            C(format_accepted_values(headername))
        ),
        C(': ').join(
            C('      Got', 'cyan'),
            C(format_header_value(value, enforced=enforced))
        )
    ))


def format_header_value(value, enforced=True):
    """ Return a formatted header value. """
    if value is None:
        return C('<not set>', 'red')

    return C(value, 'green' if enforced else 'red')


def get_headers(url):
    """ Retrieve the headers for a URL. """
    if not url.lower().startswith(('http://', 'https://')):
        url = 'http://{}'.format(url)

    resp = request.urlopen(url)
    resp.close()
    return resp.headers


def print_err(*args, **kwargs):
    """ A wrapper for print() that uses stderr by default. """
    if kwargs.get('file', None) is None:
        kwargs['file'] = sys.stderr
    print(C(' '.join(str(s) for s in args), 'red'), **kwargs)


if __name__ == '__main__':
    try:
        mainret = main(docopt(USAGESTR, version=VERSIONSTR))
    except (EOFError, KeyboardInterrupt):
        print_err('\nUser cancelled.\n', file=sys.stderr)
        mainret = 2
    except BrokenPipeError:
        print_err(
            '\nBroken pipe, input/output was interrupted.\n',
            file=sys.stderr)
        mainret = 3
    sys.exit(mainret)
