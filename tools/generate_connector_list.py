#! /usr/bin/env python
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Generate list of os-brick connectors"""

import argparse
import inspect
import json
import operator
import os
from pydoc import locate
import textwrap

from os_brick.initiator import connector

parser = argparse.ArgumentParser(prog="generate_connector_list")

parser.add_argument("--format", default='str', choices=['str', 'dict'],
                    help="Output format type")

# Keep backwards compatibilty with the gate-docs test
# The tests pass ['docs'] on the cmdln, but it's never been used.
parser.add_argument("output_list", default=None, nargs='?')


def _ensure_loaded(connector_list):
    """Loads everything in a given path.

    This will make sure all classes have been loaded and therefore all
    decorators have registered class.

    :param start_path: The starting path to load.
    """
    classes = []
    for conn in connector_list:
        try:
            conn_class = locate(conn)
            classes.append(conn_class)
        except Exception:
            pass

    return classes


def get_connectors():
    """Get a list of all connectors."""
    classes = _ensure_loaded(connector._get_connector_list())
    return [DriverInfo(x) for x in classes]


class DriverInfo(object):
    """Information about Connector implementations."""

    def __init__(self, cls):
        self.cls = cls
        self.desc = cls.__doc__
        self.class_name = cls.__name__
        self.class_fqn = '{}.{}'.format(inspect.getmodule(cls).__name__,
                                        self.class_name)
        self.platform = getattr(cls, 'platform', None)
        self.os_type = getattr(cls, 'os_type', None)

    def __str__(self):
        return self.class_name

    def __repr__(self):
        return self.class_fqn

    def __hash__(self):
        return hash(self.class_fqn)


class Output(object):

    def __init__(self, base_dir, output_list):
        # At this point we don't care what was passed in, just a trigger
        # to write this out to the doc tree for now
        self.connector_file = None
        if output_list:
            self.connector_file = open(
                '%s/doc/source/connectors.rst' % base_dir, 'w+')
            self.connector_file.write('===================\n')
            self.connector_file.write('Available Connectors\n')
            self.connector_file.write('===================\n\n')

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self.connector_file:
            self.connector_file.close()

    def write(self, text):
        if self.connector_file:
            self.connector_file.write('%s\n' % text)
        else:
            print(text)


def format_description(desc, output):
    desc = desc or '<None>'
    lines = desc.rstrip('\n').split('\n')
    output.write('* Description: %s' % lines[0])
    output.write('')
    output.write(textwrap.dedent('\n'.join(lines[1:])))


def format_options(connector_options, output):
    if connector_options and len(connector_options) > 0:

        output.write('* Driver Configuration Options:')
        output.write('')
        output.write('.. list-table:: **Driver configuration options**')
        output.write('   :header-rows: 1')
        output.write('   :widths: 14 30')
        output.write('')
        output.write('   * - Name = Default Value')
        output.write('     - (Type) Description')
        sorted_options = sorted(connector_options,
                                key=operator.attrgetter('name'))
        for opt in sorted_options:
            output.write('   * - %s = %s' %
                         (opt.name, opt.default))
            output.write('     - (%s) %s' % (opt.type, opt.help))
        output.write('')


def print_connectors(connectors, config_name, output, section_char='-'):
    for conn in sorted(connectors, key=lambda x: x.class_name):
        conn_name = conn.class_name
        output.write(conn_name)
        output.write(section_char * len(conn_name))
        if conn.platform:
            output.write('* Platform: %s' % conn.platform)
        if conn.os_type:
            output.write('* OS Type: %s' % conn.os_type)
        output.write('* %s=%s' % (config_name, conn.class_fqn))
        format_description(conn.desc, output)
        output.write('')
    output.write('')


def output_str(cinder_root, args):
    with Output(cinder_root, args.output_list) as output:
        output.write('Connectors')
        output.write('==============')
        connectors = get_connectors()

        print_connectors(connectors, 'connector', output, '~')


def collect_connector_info(connector):
    """Build the dictionary that describes this connector."""

    info = {'name': connector.class_name,
            'fqn': connector.class_fqn,
            'description': connector.desc,
            'platform': connector.platform,
            'os_type': connector.os_type,
            }

    return info


def output_dict():
    """Output the results as a JSON dict."""

    connector_list = []
    connectors = get_connectors()
    for conn in connectors:
        connector_list.append(collect_connector_info(conn))

    print(json.dumps(connector_list))


def main():
    tools_dir = os.path.dirname(os.path.abspath(__file__))
    brick_root = os.path.dirname(tools_dir)
    cur_dir = os.getcwd()
    os.chdir(brick_root)
    args = parser.parse_args()

    try:
        if args.format == 'str':
            output_str(brick_root, args)
        elif args.format == 'dict':
            output_dict()
    finally:
        os.chdir(cur_dir)


if __name__ == '__main__':
    main()
