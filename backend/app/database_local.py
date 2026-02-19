"""
Local dev database using mongomock-motor (in-memory MongoDB).
No real MongoDB installation required for local testing.
"""
import os
from mongomock_motor import AsyncMongoMockClient

DB_NAME = "agentless_security"
client = None
db = None


async def connect_db():
    global client, db
    client = AsyncMongoMockClient()
    db = client[DB_NAME]
    print("Connected to in-memory MongoDB (mongomock-motor)")


async def close_db():
    global client
    if client:
        client.close()


def get_db():
    return db
