import email
import sys
import json

if sys.version_info >= (3, 12, 0):
    import six
    sys.modules['kafka.vendor.six.moves'] = six.moves

from kafka import KafkaProducer
from pathlib import Path
import logging

# Change logging to write to a file instead of stdout to avoid interfering with Postfix communication
logging.basicConfig(
    filename='/var/log/postfix_kafka.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# This is invoked by the postfix server.

class PostfixKafkaPipeline:
    def __init__(self, kafka_bootstrap_servers, kafka_topic):
        """Initialize the pipeline with Kafka configuration."""
        self.producer = KafkaProducer(
            bootstrap_servers=kafka_bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        self.kafka_topic = kafka_topic

    def parse_email(self, email_content):
        """
        Parse email content into a structured format with comprehensive recipient information.
        
        Returns:
            dict: Parsed email with standardized fields including proper recipient counts
        """
        try:
            msg = email.message_from_string(email_content)
            
            # Helper function to parse address fields
            def parse_addresses(field):
                if not field:
                    return []
                # Handle both comma-separated and semicolon-separated lists
                addresses = field.replace(';', ',').split(',')
                return [addr.strip() for addr in addresses if '@' in addr]

            # Parse all recipient fields
            to_recipients = parse_addresses(msg.get('to', ''))
            cc_recipients = parse_addresses(msg.get('cc', ''))
            # Note: BCC won't be available in received emails
            
            parsed_email = {
                'headers': dict(msg.items()),
                'from': msg.get('from', ''),
                'to': msg.get('to', ''),  # Keep original string for compatibility
                'cc': msg.get('cc', ''),  # Add CC field
                'subject': msg.get('subject', ''),
                'date': msg.get('date', ''),
                'body': '',
                'attachments': [],
                # Add pre-computed counts for downstream processing
                'to_count': len(to_recipients),
                'cc_count': len(cc_recipients),
                'total_recipients': len(to_recipients) + len(cc_recipients),
                # Store parsed recipient lists if needed
                'to_list': to_recipients,
                'cc_list': cc_recipients
            }

            # Extract body with better handling of multipart messages
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == 'text/plain':
                        payload = part.get_payload(decode=True)
                        if payload:
                            parsed_email['body'] += payload.decode(errors='replace')
                    elif part.get_content_maintype() != 'multipart':
                        parsed_email['attachments'].append({
                            'filename': part.get_filename(),
                            'content_type': part.get_content_type(),
                            'size': len(part.get_payload(decode=True)) if part.get_payload() else 0
                        })
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    parsed_email['body'] = payload.decode(errors='replace')

            return parsed_email
            
        except Exception as e:
            logger.error(f"Error parsing email: {e}")
            return None

    def process_email(self):
        """Read email from stdin and process it."""
        try:
            email_content = sys.stdin.read()
            parsed_email = self.parse_email(email_content)
            
            if parsed_email:
                try:
                    # Send to Kafka topic
                    self.producer.send(
                        self.kafka_topic,
                        value=parsed_email
                    )
                    self.producer.flush()
                    logger.info("Email successfully sent to Kafka topic")
                    # Write success response to Postfix
                    sys.stdout.write("200 Message processed successfully\n")
                    sys.stdout.flush()
                    return True
                except Exception as e:
                    logger.error(f"Error sending to Kafka: {e}")
                    sys.stdout.write("400 Error processing message\n")
                    sys.stdout.flush()
                    return False
            else:
                sys.stdout.write("400 Error parsing message\n")
                sys.stdout.flush()
                return False
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            sys.stdout.write("400 Unexpected error\n")
            sys.stdout.flush()
            return False

def main():
    # Configuration
    KAFKA_BOOTSTRAP_SERVERS = 'localhost:9092'
    KAFKA_TOPIC = 'email-security'

    try:
        # Create and run pipeline
        pipeline = PostfixKafkaPipeline(KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC)
        success = pipeline.process_email()
        sys.exit(0 if success else 1)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.stdout.write("400 Fatal error occurred\n")
        sys.stdout.flush()
        sys.exit(1)

if __name__ == "__main__":
    main()