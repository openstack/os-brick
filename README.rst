========================
Team and repository tags
========================

.. image:: https://governance.openstack.org/tc/badges/os-brick.svg
    :target: https://governance.openstack.org/tc/reference/tags/index.html

.. Change things from this point on

===============================
brick
===============================

.. image:: https://img.shields.io/pypi/v/os-brick.svg
    :target: https://pypi.org/project/os-brick/
    :alt: Latest Version

.. image:: https://img.shields.io/pypi/dm/os-brick.svg
    :target: https://pypi.org/project/os-brick/
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

For any other information, refer to the developer documents:
  https://docs.openstack.org/os-brick/latest/
OR refer to the parent project, Cinder:
  https://docs.openstack.org/cinder/latest/
Release notes for the project can be found at:
  https://docs.openstack.org/releasenotes/os-brick

* License: Apache License, Version 2.0
* Source: https://git.openstack.org/cgit/openstack/os-brick
* Bugs: https://bugs.launchpad.net/os-brick
