===============================
brick
===============================

.. image:: https://img.shields.io/pypi/v/os-brick.svg
    :target: https://pypi.python.org/pypi/os-brick/
    :alt: Latest Version

.. image:: https://img.shields.io/pypi/dm/os-brick.svg
    :target: https://pypi.python.org/pypi/os-brick/
    :alt: Downloads

OpenStack Cinder brick library for managing local volume attaches


Features
--------

* Discovery of volumes being attached to a host for many transport protocols.
* Removal of volumes from a host.

Hacking
-------

Hacking on brick requires python-gdbm (for Debian derived distributions),
Python 2.7 and Python 3.4. A recent tox is required, as is a recent virtualenv
(13.1.0 or newer).

If "tox -e py34" fails with the error "db type could not be determined", remove
the .testrepository/ directory and then run "tox -e py34".

For any other imformation, refer to the parent project, Cinder:
  https://github.com/openstack/cinder

* License: Apache License, Version 2.0
* Source: http://git.openstack.org/cgit/openstack/os-brick
* Bugs: http://bugs.launchpad.net/os-brick
