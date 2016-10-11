RabbitMQ
========

Installation
------------

Apt-get ::

  # apt-get install rabbitmq-server

Configuration (for remote access)
---------------------------------

Edit ``/etc/rabbitmq/rabbitmq.config`` and change/add ``[{rabbit, [{loopback_users, []}]}].``

Restart Rabbitmq ::

  # service rabbitmq-server restart
