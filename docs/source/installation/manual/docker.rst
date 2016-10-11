Docker
======

Installation
------------
::

  # curl -sSL https://get.docker.com/ | s

Configuration
-------------

Add right to your user for using Docker (maybe other methods are available) ::

  # groupadd docker
  # gpasswd -a <your user> docker
  # service docker restart


Logout and login to apply changes
