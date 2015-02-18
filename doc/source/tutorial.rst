Tutorial
========

This tutorial is intended as an introduction to working with
**os-brick**.

Prerequisites
-------------
Before we start, make sure that you have the **os-brick** distribution
:doc:`installed <installation>`. In the Python shell, the following
should run without raising an exception:

.. code-block:: bash

  >>> import os_brick

Fetch all of the initiator information from the host
----------------------------------------------------
An example of how to collect the initiator information that is needed
to export a volume to this host.

.. code-block:: python

 from os_brick.initiator import connector

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
