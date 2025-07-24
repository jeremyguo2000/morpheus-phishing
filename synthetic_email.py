import sys
if sys.version_info >= (3, 12, 0):
    import six
    sys.modules['kafka.vendor.six.moves'] = six.moves

import json
import random
from datetime import datetime, timedelta
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from kafka import KafkaProducer
import logging
from email_to_kafka import PostfixKafkaPipeline


logging.basicConfig(
    filename='/var/log/synthetic_email_kafka.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DataGenerator:
    """Simple data generation utility to replace Faker dependency"""
    
    FIRST_NAMES = [
        "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", 
        "Linda", "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", 
        "Joseph", "Jessica", "Thomas", "Sarah", "Charles", "Karen"
    ]
    
    LAST_NAMES = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
        "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
        "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin"
    ]
    
    BUSINESS_WORDS = [
        "synergy", "strategy", "innovation", "optimization", "solutions",
        "analytics", "marketing", "operations", "development", "research",
        "implementation", "infrastructure", "security", "compliance", "project",
        "initiative", "platform", "framework", "methodology", "architecture"
    ]
    
    CITIES = [
        "New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia",
        "San Antonio", "San Diego", "Dallas", "San Jose", "Austin", "Jacksonville",
        "Fort Worth", "Columbus", "San Francisco", "Charlotte", "Indianapolis",
        "Seattle", "Denver", "Boston"
    ]
    
    @classmethod
    def name(cls):
        return f"{random.choice(cls.FIRST_NAMES)} {random.choice(cls.LAST_NAMES)}"
    
    @classmethod
    def business_phrase(cls):
        return " ".join(random.sample(cls.BUSINESS_WORDS, 3))
    
    @classmethod
    def city(cls):
        return random.choice(cls.CITIES)
    
    @classmethod
    def date_this_month(cls):
        now = datetime.now()
        start_of_month = now.replace(day=1)
        if now.month == 12:
            end_of_month = now.replace(year=now.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            end_of_month = now.replace(month=now.month + 1, day=1) - timedelta(days=1)
        
        random_day = start_of_month + timedelta(
            days=random.randint(0, (end_of_month - start_of_month).days)
        )
        return random_day.strftime("%Y-%m-%d")
    
    @classmethod
    def random_number(cls, digits):
        return str(random.randint(10 ** (digits - 1), (10 ** digits) - 1))
    
    @classmethod
    def uuid4(cls):
        random_hex = lambda: hex(random.randint(0, 15))[2:]
        return "-".join([
            ''.join(random_hex() for _ in range(8)),
            ''.join(random_hex() for _ in range(4)),
            ''.join(random_hex() for _ in range(4)),
            ''.join(random_hex() for _ in range(4)),
            ''.join(random_hex() for _ in range(12))
        ])
    
    @classmethod
    def ip_v4(cls):
        return ".".join(str(random.randint(0, 255)) for _ in range(4))

class SyntheticEmailGenerator:
    def __init__(self, phishing_probability=0.2):
        """Initialize the synthetic email generator with configurable phishing probability."""
        self.phishing_probability = phishing_probability
        self.data_gen = DataGenerator
        
        # Common email domains for legitimate emails
        self.legitimate_domains = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'company.com', 'enterprise.org', 'business.net'
        ]
        
        # Slightly misspelled domains for phishing
        self.phishing_domains = [
            'gmai1.com', 'yah00.com', 'hotmai1.com', 'outlook-secure.com',
            'company-verify.com', 'enterprise-update.org', 'business-secure.net'
        ]

    def generate_normal_email(self):
        """Generate a legitimate-looking email."""
        msg = MIMEMultipart()
        
        # Generate legitimate sender and recipient addresses
        sender_domain = random.choice(self.legitimate_domains)
        sender_name = self.data_gen.name()
        sender_email = f"{sender_name.lower().replace(' ', '.')}@{sender_domain}"
        
        # Generate 1-3 recipients
        num_recipients = random.randint(1, 3)
        recipients = [
            f"{self.data_gen.name().lower().replace(' ', '.')}@{random.choice(self.legitimate_domains)}"
            for _ in range(num_recipients)
        ]
        
        # Common business email subjects
        subjects = [
            f"Meeting reminder: {self.data_gen.business_phrase()}",
            f"Project update: {self.data_gen.business_phrase()}",
            f"Invoice #{self.data_gen.random_number(6)}",
            f"Weekly report - {self.data_gen.date_this_month()}",
            "Team lunch next week",
            "Quarterly review meeting"
        ]
        
        msg['From'] = f"{sender_name} <{sender_email}>"
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = random.choice(subjects)
        msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')
        
        # Generate legitimate-looking body
        body_templates = [
            "Hi team,\n\nJust following up on our discussion about {topic}. "
            "Could we schedule a meeting for next week to discuss this further?\n\n"
            "Best regards,\n{name}",
            
            "Hello,\n\nI've reviewed the latest {topic} report and everything looks good. "
            "Please let me know if you need any clarification.\n\n"
            "Thanks,\n{name}",
            
            "Good morning,\n\nAttached is the updated {topic} document for your review. "
            "I've highlighted the key changes in the summary section.\n\n"
            "Regards,\n{name}"
        ]
        
        body = random.choice(body_templates).format(
            topic=self.data_gen.business_phrase(),
            name=sender_name
        )
        
        msg.attach(MIMEText(body, 'plain'))
        return msg

    def generate_phishing_email(self):
        """Generate a suspicious-looking phishing email."""
        msg = MIMEMultipart()
        
        # Generate suspicious sender information
        legitimate_domain = random.choice(self.legitimate_domains)
        phishing_domain = random.choice(self.phishing_domains)
        sender_name = self.data_gen.name()
        
        # Use either a spoofed legitimate domain or an obviously suspicious one
        sender_email = (
            f"{sender_name.lower().replace(' ', '.')}@{phishing_domain}"
            if random.random() > 0.5
            else f"security@{legitimate_domain}-verify.com"
        )
        
        # Generate recipients (usually more than normal emails)
        num_recipients = random.randint(3, 8)
        recipients = [
            f"{self.data_gen.name().lower().replace(' ', '.')}@{random.choice(self.legitimate_domains)}"
            for _ in range(num_recipients)
        ]
        
        # Suspicious subject lines
        subjects = [
            "URGENT: Account Security Verification Required",
            "Important: Immediate Action Required - Account Access",
            f"Security Alert - Suspicious Login from {self.data_gen.city()}",
            "Password Reset Required Within 24 Hours",
            "Verify Your Account Details Now",
            f"[IMPORTANT] New Sign-in from {self.data_gen.ip_v4()}"
        ]
        
        msg['From'] = f"{sender_name} <{sender_email}>"
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = random.choice(subjects)
        msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')
        
        # Generate phishing email body
        body_templates = [
            "Dear valued user,\n\nWe have detected suspicious activity on your account. "
            "Please verify your account immediately by clicking the secure link below:\n\n"
            "https://{phishing_domain}/secure-verify?token={token}\n\n"
            "Failure to verify within 24 hours will result in account suspension.\n\n"
            "Security Team",
            
            "ATTENTION: Your account access will be terminated unless verified.\n\n"
            "We recently noticed unusual login attempts from {location}. "
            "To secure your account, please confirm your identity:\n\n"
            "https://{phishing_domain}/account-verify?id={token}\n\n"
            "This is an automated message, please do not reply.",
            
            "Important Notice:\n\nDue to recent security updates, all users must "
            "verify their account information. Click below to continue:\n\n"
            "https://{phishing_domain}/security-update?user={token}\n\n"
            "Your immediate attention is required.\n\nIT Security Department"
        ]
        
        body = random.choice(body_templates).format(
            phishing_domain=phishing_domain,
            token=self.data_gen.uuid4(),
            location=self.data_gen.city()
        )
        
        msg.attach(MIMEText(body, 'plain'))
        return msg

class SyntheticEmailKafkaPipeline:
    def __init__(self, kafka_bootstrap_servers, kafka_topic, phishing_probability=0.2):
        """Initialize the pipeline with Kafka configuration and phishing probability."""
        self.producer = KafkaProducer(
            bootstrap_servers=kafka_bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        self.kafka_topic = kafka_topic
        self.email_generator = SyntheticEmailGenerator(phishing_probability)
        self.parser = PostfixKafkaPipeline(kafka_bootstrap_servers, kafka_topic)

    def generate_and_send(self):
        """Generate a synthetic email and send it to Kafka."""
        try:
            # Determine if this should be a phishing email
            is_phishing = random.random() < self.email_generator.phishing_probability
            print("\n is_phishing ground truth: ", is_phishing)
            # Generate appropriate email type
            email_msg = (
                self.email_generator.generate_phishing_email()
                if is_phishing
                else self.email_generator.generate_normal_email()
            )
            
            # Convert email to string format
            email_content = email_msg.as_string()
            
            print("\n email_content: ", email_content)

            # Parse email using existing parser
            parsed_email = self.parser.parse_email(email_content)
            
            # Add metadata about synthetic nature and classification
            parsed_email['metadata'] = {
                'synthetic': True,
                'is_phishing': is_phishing,
                'generated_at': datetime.now().isoformat(),
                'generation_type': 'phishing' if is_phishing else 'normal'
            }
            
            # Send to Kafka
            self.producer.send(self.kafka_topic, value=parsed_email)
            self.producer.flush()
            logger.info(f"Synthetic email (phishing={is_phishing}) sent to Kafka topic")
            return True
            
        except Exception as e:
            logger.error(f"Error generating/sending synthetic email: {e}")
            return False

def main():
    # Configuration
    KAFKA_BOOTSTRAP_SERVERS = 'localhost:9092'
    KAFKA_TOPIC = 'email-security'
    PHISHING_PROBABILITY = 0.2  # 20% chance of generating phishing emails
    GENERATION_INTERVAL = 60  # Generate an email every 10 seconds
    
    try:
        pipeline = SyntheticEmailKafkaPipeline(
            KAFKA_BOOTSTRAP_SERVERS,
            KAFKA_TOPIC,
            PHISHING_PROBABILITY
        )
        
        while True:
            success = pipeline.generate_and_send()
            if not success:
                logger.warning("Failed to generate/send email, retrying in next interval")
            print('going to sleep...\n')
            time.sleep(GENERATION_INTERVAL)
            print("woke up ")

            
    except Exception as e:
        logger.error(f"Fatal error in synthetic email generation: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()