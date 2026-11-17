from datetime import datetime, timezone
from bson import ObjectId
from pymongo import ReturnDocument
from hashlib import sha256


class UserSession:
    collection = None  # Set this to your MongoDB collection (e.g., mongo.db.user_sessions)

    def __init__(self, user_id, session_id, ip_address, organization_id, created_at=None, updated_at=None, _id=None):
        # Ensure user_id is stored as an ObjectId
        self.user_id = ObjectId(user_id) if isinstance(user_id, str) else user_id
        self.session_id = session_id
        self.ip_address = ip_address
        self.organization_id = organization_id
        self.created_at = created_at or datetime.now(timezone.utc)
        self.updated_at = updated_at or datetime.now(timezone.utc)
        self.id = _id  # MongoDB ObjectId

    def to_dict(self):
        return {
            "user_id": self.user_id,
            "session_id": self.session_id,
            "ip_address": self.ip_address,
            "organization_id": self.organization_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            user_id=data.get("user_id"),
            session_id=data.get("session_id"),
            ip_address=data.get("ip_address"),
            organization_id=data.get("organization_id"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            _id=data.get("_id")
        )

    @classmethod
    def save_or_update(cls, user_id, session_id, ip_address, organization_id):
        if cls.collection is None:
            raise RuntimeError("UserSession.collection is not initialized.")

        now = datetime.now(timezone.utc)
        user_id = ObjectId(user_id) if isinstance(user_id, str) else user_id

        # An owner-scoped, deterministic key also makes concurrent registration idempotent.
        key = f"{user_id}:{sha256(session_id.encode()).hexdigest()}"
        fields = {"user_id": user_id, "session_id": session_id, "ip_address": ip_address,
                  "organization_id": organization_id, "updated_at": now, "verified_owner": True}
        doc = cls.collection.find_one_and_update(
            {"_id": key}, {"$set": fields, "$setOnInsert": {"created_at": now}},
            upsert=True, return_document=ReturnDocument.AFTER,
        )
        return cls.from_dict(doc)

    @classmethod
    def get_latest_session_by_org_id(cls, user_id, organization_id):
        if cls.collection is None:
            raise RuntimeError("UserSession.collection is not initialized.")

        doc = cls.collection.find_one(
            {"user_id": ObjectId(user_id), "organization_id": organization_id, "verified_owner": True},
            sort=[("updated_at", -1)]
        )
        return cls.from_dict(doc) if doc else None
    
    @classmethod
    def get_by_session_id(cls, user_id, session_id):
        if cls.collection is None:
            raise RuntimeError("UserSession.collection is not initialized.")

        doc = cls.collection.find_one({"user_id": ObjectId(user_id), "session_id": session_id, "verified_owner": True})
        return cls.from_dict(doc) if doc else None
