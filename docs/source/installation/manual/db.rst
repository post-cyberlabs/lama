Database
========

Installation of PostgreSql
--------------------------

Apt-get ::

  # apt-get install postgresl-9.4 postgresql-server-dev-9.4


Configure Postgresql (for remote access)
----------------------------------------

Edit ```/etc/postgresql/9.1/main/postgresql.conf``
and change for this ```listen_addresses='localhost' --> listen_addresses='*'``

Edit ``/etc/postgresql/8.3/main/pg_hba.conf*``
and add ```host    all         all         0.0.0.0/0            md5``

Create Database
---------------

Switch to postgres user::

  $ su postgres
  $ psql -c "CREATE USER <db username> WITH PASSWORD '<db password>';"
  $ psql -c "CREATE DATABASE lama;"
  $ psql -c "GRANT ALL PRIVILEGES ON DATABASE lama to <db username>;"

Restart Postgresql
------------------
::

  # service postgresql restart
