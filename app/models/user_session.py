from datetime import datetime, timezone
from bson import ObjectId


class UserSession:
    collection = None  # Set this to your MongoDB collection (e.g., mongo.db.user_sessions)

    def __init__(self, user_id, session_id, ip_address, created_at=None, updated_at=None, _id=None):
        # Ensure user_id is stored as an ObjectId
        self.user_id = ObjectId(user_id) if isinstance(user_id, str) else user_id
        self.session_id = session_id
        self.ip_address = ip_address
        self.created_at = created_at or datetime.now(timezone.utc)
        self.updated_at = updated_at or datetime.now(timezone.utc)
        self.id = _id  # MongoDB ObjectId

    def to_dict(self):
        return {
            "user_id": self.user_id,
            "session_id": self.session_id,
            "ip_address": self.ip_address,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            user_id=data.get("user_id"),
            session_id=data.get("session_id"),
            ip_address=data.get("ip_address"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            _id=data.get("_id")
        )

    @classmethod
    def save_or_update(cls, user_id, session_id, ip_address):
        if cls.collection is None:
            raise RuntimeError("UserSession.collection is not initialized.")

        now = datetime.now(timezone.utc)
        user_id = ObjectId(user_id) if isinstance(user_id, str) else user_id

        existing = cls.collection.find_one({"session_id": session_id})
        if existing:
            cls.collection.update_one(
                {"_id": existing["_id"]},
                {"$set": {
                    "user_id": user_id,
                    "ip_address": ip_address,
                    "updated_at": now
                }}
            )
            return cls.from_dict({
                **existing,
                "user_id": user_id,
                "ip_address": ip_address,
                "updated_at": now
            })

        else:
            doc = {
                "user_id": user_id,
                "session_id": session_id,
                "ip_address": ip_address,
                "created_at": now,
                "updated_at": now
            }
            result = cls.collection.insert_one(doc)
            doc["_id"] = result.inserted_id
            return cls.from_dict(doc)

    @classmethod
    def get_latest_session_by_ip(cls, ip_address):
        if cls.collection is None:
            raise RuntimeError("UserSession.collection is not initialized.")

        doc = cls.collection.find_one(
            {"ip_address": ip_address},
            sort=[("updated_at", -1)]
        )
        return cls.from_dict(doc) if doc else None
