# whistledrop/whistledrop_server/models.py
from flask_login import UserMixin
from . import key_manager # To access get_journalist_by_id

class Journalist(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

    @staticmethod
    def get(user_id):
        """
        Required by Flask-Login.
        Retrieves a user by their ID.
        """
        journalist_data = key_manager.get_journalist_by_id(user_id)
        if journalist_data:
            return Journalist(id=journalist_data['id'], username=journalist_data['username'])
        return None

    def get_id(self):
        """
        Required by Flask-Login.
        Returns the unique ID for the user (which is self.id).
        """
        return str(self.id)