========================
Team and repository tags
========================

.. image:: https://governance.openstack.org/tc/badges/os-brick.svg
    :target: https://governance.openstack.org/tc/reference/tags/index.html

.. Change things from this point on

=====
brick
=====

.. image:: https://img.shields.io/pypi/v/os-brick.svg
    :target: https://pypi.org/project/os-brick/
    :alt: Latest Version

.. image:: https://img.shields.io/pypi/dm/os-brick.svg
    :target: https://pypi.org/project/os-brick/
    :alt: Downloads

OpenStack Cinder brick library for managing local volume attaches


.. warning::
   The stable/wallaby branch of os-brick does not contain a fix for
   CVE-2023-2088_.  Be aware that such a fix must span cinder, os-brick,
   nova, and, depending on your deployment configuration, glance_store
   and ironic.  *The Cinder project team advises against using the code
   in this branch unless a mitigation against CVE-2023-2088 is applied.*

   .. _CVE-2023-2088: https://nvd.nist.gov/vuln/detail/CVE-2023-2088

   References:

   * https://nvd.nist.gov/vuln/detail/CVE-2023-2088
   * https://bugs.launchpad.net/cinder/+bug/2004555
   * https://security.openstack.org/ossa/OSSA-2023-003.html
   * https://wiki.openstack.org/wiki/OSSN/OSSN-0092

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
* Source: https://opendev.org/openstack/os-brick
* Bugs: https://bugs.launchpad.net/os-brick
