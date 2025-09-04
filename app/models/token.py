from bson import ObjectId
from datetime import datetime, timezone

class Token:
    collection = None  # Set this in your app setup: Token.collection = mongo.db.tokens

    def __init__(self, token_dict):
        if not token_dict:
            raise ValueError("token_dict cannot be None or empty")
        self.token_dict = token_dict
        self.id = str(token_dict["_id"])  # Keep as string if exposed externally

    @property
    def token(self):
        return self.token_dict.get("token")

    @property
    def user_id(self):
        return self.token_dict.get("user_id")

    @property
    def token_type(self):
        return self.token_dict.get("token_type")

    @property
    def created_at(self):
        return self.token_dict.get("created_at")

    @property
    def expires_at(self):
        return self.token_dict.get("expires_at")

    @classmethod
    def create(cls, user_id, token_type, token):
        if cls.collection is None:
            raise RuntimeError("Token.collection is not initialized.")

        now = datetime.now(timezone.utc)
        token_data = {
            "user_id": ObjectId(user_id) if isinstance(user_id, str) else user_id,
            "token_type": token_type,
            "token": token,
            "created_at": now,
            "expires_at": None
        }

        result = cls.collection.insert_one(token_data)
        token_data["_id"] = result.inserted_id
        return cls(token_data)

    @classmethod
    def get_latest(cls, user_id, token_type):
        if cls.collection is None:
            raise RuntimeError("Token.collection is not initialized.")

        user_id = ObjectId(user_id) if isinstance(user_id, str) else user_id
        doc = cls.collection.find_one(
            {"user_id": user_id, "token_type": token_type},
            sort=[("created_at", -1)]
        )
        return cls(doc) if doc else None

    @classmethod
    def get_by_user_id_and_type(cls, user_id, token_type):
        return cls.get_latest(user_id, token_type)
