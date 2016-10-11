Initialisation
==============

Before running LAMA, you need to build Docker containers on the machine with Docker.

For that ::

  $ cd lama/Docker
  $ ./build_docker.sh

It can take a long time.

You can build only selected containers ``./build_docker.sh -f <folder1> --folder <folder2>``.

You can add ``-u`` or ``--update`` option to update all containers.

You can add ``-q`` or ``--quiet`` option to remove output from Docker build command.
