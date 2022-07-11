========
Tutorial
========

This tutorial is intended as an introduction to working with **os-brick**.

Prerequisites
-------------

Before we start, make sure that you have the **os-brick** distribution
:doc:`installed </install/index>`. In the Python shell, the following should
run without raising an exception:

.. code-block:: bash

   >>> import os_brick

Configuration
-------------

There are some os-brick connectors that use file locks to prevent concurrent
access to critical sections of the code.

These file locks use the ``oslo.concurrency`` ``lock_utils`` module and require
the ``lock_path`` to be configured with the path where locks should be created.

os-brick can use a specific directory just for its locks or use the same
directory as the service using os-brick.

The os-brick specific configuration option is ``[os_brick]/lock_path``, and if
left undefined it will use the value from ``[oslo_concurrency]/lock_path``.

Setup
-----

Once os_brick has been loaded it needs to be initialized, which is done by
calling the ``os_brick.setup`` method with the ``oslo.conf`` configuration.

It is important that the call to ``setup`` method happens **after** oslo.config
has been properly initialized.

.. code-block:: python

   from oslo_config import cfg
   from cinder import version

   CONF = cfg.CONF

   def main():
       CONF(sys.argv[1:], project='cinder',
            version=version.version_string())
       os_brick.setup(CONF)

Fetch all of the initiator information from the host
----------------------------------------------------

An example of how to collect the initiator information that is needed to export
a volume to this host.

.. code-block:: python

   from os_brick.initiator import connector


   os_brick.setup(CONF)

   # what helper do you want to use to get root access?
   root_helper = "sudo"
   # The ip address of the host you are running on
   my_ip = "192.168.1.1"
   # Do you want to support multipath connections?
   multipath = True
   # Do you want to enforce that multipath daemon is running?
   enforce_multipath = False
   initiator = connector.get_connector_properties(root_helper, my_ip,
                                                  multipath,
                                                  enforce_multipath)
