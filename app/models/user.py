from bson import ObjectId
from flask_login import UserMixin
from datetime import datetime, timezone, timedelta

class User(UserMixin):
    collection = None  # to be set in app factory

    def __init__(self, user_dict):
        self.user_dict = user_dict
        self.id = str(user_dict["_id"])  # Flask-Login requires ID as a string

    def get_id(self):
        return self.id

    @property
    def email(self):
        return self.user_dict.get("email")

    @property
    def is_email_verified(self):
        return self.user_dict.get("isEMailVerify", False)

    @classmethod
    def get_by_email(cls, email):
        user_data = cls.collection.find_one({"email": email})
        if user_data:
            return cls(user_data)
        return None

    @classmethod
    def create(cls, email):
        now = datetime.now(timezone.utc)
        user_id = ObjectId()
        api_key = str(ObjectId())  # Unique API key string

        user_data = {
            "_id": user_id,
            "email": email,
            "api_key": api_key,
            "createdAt": now,
            "updatedAt": now,
            "email_token": None,
            "email_token_expires": None,
            "isEmailVerify": False  # Default to not verified
        }
        cls.collection.insert_one(user_data)
        return cls(user_data)

    @classmethod
    def get(cls, user_id):
        try:
            obj_id = ObjectId(user_id)
        except Exception:
            return None
        user_data = cls.collection.find_one({"_id": obj_id})
        if user_data:
            return cls(user_data)
        return None

    @classmethod
    def save_email_token(cls, email, token):
        """Save a one-time login token to the user document (expires in 24 hours)"""
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        result = cls.collection.update_one(
            {"email": email},
            {"$set": {
                "email_token": token,
                "email_token_expires": expires_at,
                "updatedAt": datetime.now(timezone.utc)
            }}
        )
        return result.modified_count == 1

    @classmethod
    def get_by_email_token(cls, email, token):
        """Validate token and return user"""
        now = datetime.now(timezone.utc)
        user_data = cls.collection.find_one({
            "email": email,
            "email_token": token,
            "email_token_expires": {"$gt": now}
        })
        if user_data:
            return cls(user_data)
        return None

    def clear_email_token(self):
        """Clear token after use"""
        User.collection.update_one(
            {"_id": ObjectId(self.id)},
            {"$set": {
                "email_token": None,
                "email_token_expires": None
            }}
        )

    @classmethod
    def verify_email(cls, email):
        """Set isEmailVerify to True after successful verification"""
        result = cls.collection.update_one(
            {"email": email},
            {"$set": {
                "isEmailVerify": True,
                "updatedAt": datetime.now(timezone.utc)
            }}
        )
        return result.modified_count == 1

    @classmethod
    def get_by_api_key(cls, api_key):
        user_data = cls.collection.find_one({"api_key": api_key})
        if user_data:
            return cls(user_data)
        return None

# import uuid
# from flask_login import UserMixin
# from datetime import datetime, timezone

# class User(UserMixin):
#     collection = None  # to be set in app factory

#     def __init__(self, user_dict):
#         self.user_dict = user_dict
#         self.id = user_dict["_id"]

#     def get_id(self):
#         return self.id

#     @property
#     def email(self):
#         return self.user_dict.get("email")

#     @classmethod
#     def generate_api_key(cls, user_id):
#         """Generate a UUIDv4 token as API key and save it"""
#         new_api_key = str(uuid.uuid4())
#         now = datetime.now(timezone.utc)

#         result = cls.collection.update_one(
#             {"_id": user_id},
#             {"$set": {"api_key": new_api_key, "updatedAt": now}}
#         )
#         return new_api_key if result.modified_count == 1 else None

#     @classmethod
#     def get_by_email(cls, email):
#         user_data = cls.collection.find_one({"email": email})
#         if user_data:
#             return cls(user_data)
#         return None

#     @classmethod
#     def create(cls, email):
#         now = datetime.now(timezone.utc)
#         user_id = str(uuid.uuid4())
#         api_key = str(uuid.uuid4())  # Use UUIDv4 as API key

#         user_data = {
#             "_id": user_id,
#             "email": email,
#             "api_key": api_key,
#             "createdAt": now,
#             "updatedAt": now,
#         }
#         cls.collection.insert_one(user_data)
#         return cls(user_data)

#     @classmethod
#     def get(cls, user_id):
#         user_data = cls.collection.find_one({"_id": user_id})
#         if user_data:
#             return cls(user_data)
#         return None

#     @classmethod
#     def get_by_api_key(cls, api_key):
#         user_data = cls.collection.find_one({"api_key": api_key})
#         if user_data:
#             return cls(user_data)
#         return None
