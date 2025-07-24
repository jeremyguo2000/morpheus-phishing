#!/usr/bin/env python3
import sys
import json

if sys.version_info >= (3, 12, 0):
    import six
    sys.modules['kafka.vendor.six.moves'] = six.moves

from kafka import KafkaConsumer
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def monitor_kafka_topic():
    consumer = KafkaConsumer(
        'email-security',
        bootstrap_servers=['localhost:9092'],
        value_deserializer=lambda m: json.loads(m.decode('utf-8')),
        auto_offset_reset='earliest',  # Change to 'earliest' to consume from the beginning
        group_id='my-consumer-group'   # Added group_id to join a consumer group
    )
    
    logger.info("Starting to monitor Kafka topic 'email-security'...")
    
    try:
        for message in consumer:
            logger.info("🔔 New email received:")
            logger.info(f"From: {message.value.get('from', 'N/A')}")
            logger.info(f"To: {message.value.get('to', 'N/A')}")
            logger.info(f"Subject: {message.value.get('subject', 'N/A')}")
            logger.info("-" * 50)
            
    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user")
        consumer.close()

if __name__ == "__main__":
    monitor_kafka_topic()
