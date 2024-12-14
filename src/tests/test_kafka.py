from ..chatspy.clients import KafkaClient

kafka_client = KafkaClient(
    bootstrap_servers=[""],  # b-1.cluster.test.c2.kafka.amazonaws.com:9092
    security_protocol="SASL_SSL",
    ssl_cafile="/path/to/aws_ca_bundle.pem",
    sasl_mechanism="SCRAM-SHA-512",
    sasl_username="",
    sasl_password="",
)

message = b"Hello, I'm kafka!"

def produce_test():
    producer = kafka_client.create_producer()
    producer.send("test-topic", value=message)
    producer.flush()


def consume_test():
    consumer = kafka_client.create_consumer(topics=["test-topic"], group_id="test-group")
    for message in consumer:
        assert message.value == message, "Not working.."
