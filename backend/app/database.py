import os
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = "agentless_security"

client: AsyncIOMotorClient = None
db = None


async def connect_db():
    global client, db
    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DB_NAME]
    # Create indexes for performance
    await db.network_logs.create_index([("timestamp", -1)])
    await db.network_logs.create_index([("source_ip", 1)])
    await db.alerts.create_index([("timestamp", -1)])
    await db.alerts.create_index([("severity", 1)])
    print(f"Connected to MongoDB at {MONGO_URL}")


async def close_db():
    global client
    if client:
        client.close()
        print("MongoDB connection closed")


def get_db():
    return db
