#!/usr/bin/env python3
from prometheus_client import start_http_server, Counter
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

detection_counter = Counter('detection_total', 
                            'Total phishing and non-phishing detections',
                            ['type'])
start_http_server(9033)
DETECTION_THRESHOLD = 0.85

def monitor_kafka_topic():
    topic = 'output-email-classifications'
    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=['localhost:9092'],
        value_deserializer=lambda m: json.loads(m.decode('utf-8')),
        auto_offset_reset='earliest',  # Change to 'earliest' to consume from the beginning
        group_id='my-consumer-group'   # Added group_id to join a consumer group
    )
    
    logger.info("Starting to monitor Kafka topic " + topic)
    
    try:
        for message in consumer:
            logger.info("🔔 New notification from topic:")
            logger.info(f"Subject: {message.value.get('subject', None)}")
            is_phishing_prob = message.value.get('is_phishing', None)
            logger.info(f"Extracted 'is_phishing_prob': {is_phishing_prob}")
            logger.info("-" * 50)
            
            if is_phishing_prob > DETECTION_THRESHOLD:
                detection_counter.labels(type='phishing').inc()
            else:
                detection_counter.labels(type='non-phishing').inc()
            
            
    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user")
        consumer.close()

if __name__ == "__main__":
    monitor_kafka_topic()
