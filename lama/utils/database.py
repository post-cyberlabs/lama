"""
Database file

This module manages database.
It create tables when the database is empty.
It use PostgreSQL as driver.

"""

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import os
import logging
import configparser
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import (Table, Column, Integer, String, Float, MetaData,
                        ForeignKey, DateTime, create_engine)


class Lamadb(object):

    metadata = MetaData()
    # structure of analysis table
    analysis = Table('analysis', metadata,
                     Column('_uid', Integer, primary_key=True),
                     Column('_start_date', DateTime),
                     Column('_end_date', DateTime)
                     )

    # structure of malware table
    malware = Table('malware', metadata,
                    Column('_uid', Integer, primary_key=True),
                    Column('_parent_uid', Integer),
                    Column('_name', String),
                    Column('_path', String),
                    Column('_md5', String),
                    Column('_sha1', String),
                    Column('_mime', String),
                    Column('_size', Integer),
                    Column('_nb_module', Integer),
                    Column('_analysis_uid', None,
                           ForeignKey('analysis._uid')
                           ),
                    Column('_parent_uid', Integer,
                           ForeignKey('malware._uid'))
                    )

    # structure of module_status table
    module_status = Table('module_status', metadata,
                          Column('_uid', Integer, primary_key=True),
                          Column('_module_cls_name', String),
                          Column('_status', Integer),
                          Column('_start_analyze_date', DateTime),
                          Column('_end_analyze_date', DateTime),
                          Column('_options', String),
                          Column('_malware_uid', None,
                                 ForeignKey('malware._uid'))
                          )

    # structure of indicator table
    indicator = Table('indicator', metadata,
                      Column('_uid', Integer, primary_key=True),
                      Column('_module_cls_name', String),
                      Column('_name', String),
                      Column('_content_type', String),
                      Column('_content', String),
                      Column('_option', String),
                      Column('_score', Float),
                      Column('_module_uid', None,
                             ForeignKey('module_status._uid'))
                      )

    engine = None
    conn = None

    def init():
        config = configparser.ConfigParser()
        config.read('lama/conf/project.conf')

        # get informations for connexion
        try:
            host = config["DATABASE"]["host"]
            database = config["DATABASE"]["database"]
            user = config["DATABASE"]["user"]
            password = config["DATABASE"]["password"]
        except KeyError as e:
            logging.error("Error project.conf[DATABASE] : {} missing.".format(str(e)))
            exit(1)

        Lamadb.Base = declarative_base()
        connect = "postgresql://{}:{}@{}/{}".format(user, password, host, database)
        Lamadb.engine = create_engine(connect)
        Lamadb.conn = Lamadb.engine.connect()

    def create_db():
        """
        Create de Database
        """
        if not Lamadb.engine:
            Lamadb.init()
        Lamadb.metadata.create_all(Lamadb.engine)

    def get_conn():
        """
        Return a connexion of DB (Singleton pattern)
        """
        if not Lamadb.conn:
            Lamadb.init()
        return Lamadb.conn

    def execute(s):
        try:
            res = Lamadb.get_conn().execute(s)
        except Exception as e:
            logging.error("Error with postgresql server, check the folowing error message.")
            logging.error(str(e))
            os._exit(1)
        return res
