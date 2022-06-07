:mod:`connector` -- Connector
=============================

.. automodule:: os_brick.initiator.connector
   :synopsis: Connector module for os-brick

   .. autoclass:: os_brick.initiator.connector.InitiatorConnector

      .. automethod:: factory

   .. autoclass:: os_brick.initiator.connector.ISCSIConnector

      .. automethod:: connect_volume
      .. automethod:: disconnect_volume

   .. autoclass:: os_brick.initiator.connector.FibreChannelConnector

      .. automethod:: connect_volume
      .. automethod:: disconnect_volume

   .. autoclass:: os_brick.initiator.connector.LocalConnector

      .. automethod:: connect_volume
      .. automethod:: disconnect_volume

   .. autoclass:: os_brick.initiator.connector.HuaweiStorHyperConnector

      .. automethod:: connect_volume
      .. automethod:: disconnect_volume

   .. autoclass:: os_brick.initiator.connectors.nvmeof.NVMeOFConnector

      .. automethod:: connect_volume
      .. automethod:: disconnect_volume
      .. automethod:: extend_volume
      .. automethod:: get_volume_paths
      .. automethod:: get_connector_properties
