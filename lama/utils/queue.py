""" Queue singleton class

This class allow to publish and consume queues.

This class contains only static methods and attributes.
The analysis channel is the channel which we can send malwares\
 to be analyzed.
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
import pika
import logging
import configparser


class Queue(object):
    """ Queue class

    Attributes :
        **analysis_channel** (Rmq channel): Channel for malware analysis.
    """
    config = configparser.ConfigParser()
    config.read('lama/conf/project.conf')
    host = config.get("RABBITMQ", "host", fallback="localhost")

    # dict of connection per thread
    connections = {}
    # dict of channels per thread
    channels = {}
    # dict of running thread
    consumers = {}

    @staticmethod
    def _check_analysis_queue(queue_name, thread_id=0):
        """
        Private static method whose create the queue_name queue as singleton
        """
        # check if connection exists for the thread
        if thread_id not in Queue.connections:
            try:
                Queue.connections[thread_id] = pika.BlockingConnection(
                    pika.ConnectionParameters(Queue.host))
            except pika.exceptions.ConnectionClosed as e:
                logging.error("Error with RMQ server, check it's started.")
                os._exit(1)
            Queue.consumers[thread_id] = True
        # check if channel exists for the thread
        if queue_name not in Queue.channels\
                or Queue.channels[queue_name].is_closed:
            Queue.channels[queue_name] = Queue.connections[thread_id].channel()
            Queue.channels[queue_name].queue_declare(queue=queue_name)

    @staticmethod
    def publish_queue(queue_name, body, thread_id=0):
        """
        Static method whose can publish message in queue_name queue.

        Args :
            **body** (string): Queue_id of malware.
        """
        # check if queue_name exists
        Queue._check_analysis_queue(queue_name, thread_id)
        # send data
        Queue.channels[queue_name].basic_publish(exchange='',
                                                 routing_key=queue_name,
                                                 body=str(body))

    @staticmethod
    def consume_queue(queue_name, callback_fct, thread_id=0, time_limit=1,
                      loop=True):
        """
        Static method whose can consume queue_name queue.

        Args :
            **callback_fct** (fct): Callback for return results.\
                Prototype is : def callback(ch, method, properties, body)
        """
        Queue._check_analysis_queue(queue_name, thread_id)

        Queue.channels[queue_name].basic_consume(callback_fct,
                                                 queue=queue_name,
                                                 no_ack=True)
        # avoid start_consuming function, easier to stop like this
        while Queue.consumers[thread_id]:
            Queue.connections[thread_id].process_data_events(
                                                    time_limit=time_limit)
            if not loop:
                break

    @staticmethod
    def stop_consuming(thread_id):
        """
        Stop consuming on queue.
        """
        Queue.consumers[thread_id] = False

    @staticmethod
    def stop_consuming_all():
        """
        Strop consuming on all queue.
        """
        for th_id in Queue.consumers:
            if th_id is not 0:
                Queue.stop_consuming(th_id)
