#!/usr/bin/env python3
import os
import configparser
import paho.mqtt.client as mqtt
import json
import time

# Load configuration
config = configparser.ConfigParser()
config_path = os.path.join(os.path.dirname(__file__), 'config.ini')

if not os.path.exists(config_path):
    raise FileNotFoundError(f"Config file not found at {config_path}. Please create it based on config.ini.example")

config.read(config_path)

# MQTT Configuration
mqtt_host = config['MQTT']['host']
mqtt_port = int(config['MQTT']['port'])
mqtt_username = config['MQTT']['username']
mqtt_password = config['MQTT']['password']
mqtt_topic = config['HomeAssistant']['topic']
switch_entity = config['HomeAssistant']['switch_entity']

# Callback functions
def on_connect(client, userdata, flags, rc):
    print(f"Connected with result code {rc}")
    # Subscribe to all Home Assistant topics for debugging
    client.subscribe("homeassistant/#")
    print(f"Subscribed to homeassistant/#")

def on_message(client, userdata, msg):
    print(f"Received message on topic {msg.topic}: {msg.payload.decode()}")

def on_publish(client, userdata, mid):
    print(f"Message {mid} published")

# Initialize MQTT client
client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.on_publish = on_publish

# Set username and password
client.username_pw_set(mqtt_username, mqtt_password)

# Connect to MQTT broker
print(f"Connecting to MQTT broker at {mqtt_host}:{mqtt_port}...")
client.connect(mqtt_host, mqtt_port, 60)

# Start the loop
client.loop_start()

# Wait for connection to establish
time.sleep(2)

# Try different payload formats
payloads = [
    # Standard JSON payload
    json.dumps({"entity_id": switch_entity, "state": "on"}),
    # Simple ON payload
    "ON",
    # Lowercase on
    "on",
    # Just the state
    "on",
    # Service call format
    json.dumps({"service": "switch.turn_on", "entity_id": switch_entity})
]

# Try different topics
topics = [
    mqtt_topic,  # Original topic from config
    f"homeassistant/switch/{switch_entity.split('.')[1]}/set",
    f"homeassistant/switch/{switch_entity.split('.')[1]}/command",
    f"homeassistant/switch/{switch_entity}/set",
    "homeassistant/service/switch/turn_on"
]

print("\n=== Testing different combinations of topics and payloads ===")
for topic in topics:
    for payload in payloads:
        print(f"\nPublishing to {topic}: {payload}")
        client.publish(topic, payload)
        time.sleep(1)  # Wait a bit between publishes

print("\nTest complete. Waiting for any responses...")
time.sleep(5)  # Wait for any responses

# Disconnect
client.loop_stop()
client.disconnect()
print("Disconnected from MQTT broker")
