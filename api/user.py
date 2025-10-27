import sys
import os

def get_data_path(filename):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, filename)
    else:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)

def is_registered_user(user: str) -> bool:
    try:
        with open(get_data_path('data.txt'), 'r', encoding='utf-8') as f:
            users = f.read().strip().split(',')
        return user in users
    except Exception as e:
        print(f"is_registered_user error: {e}")
        return False

def remove_user(user: str) -> bool:
    try:
        with open(get_data_path('data.txt'), 'r+', encoding='utf-8') as f:
            users = f.read().strip().split(',')
            if user not in users:
                return False
            users.remove(user)
            f.seek(0)
            f.write(','.join(users))
            f.truncate()
        return True
    except Exception as e:
        print(f"remove_user error: {e}")
        return False

def add_user(user: str) -> bool:
    try:
        with open(get_data_path('data.txt'), 'r+', encoding='utf-8') as f:
            users = f.read().strip().split(',')
            if user in users:
                return False
            users.append(user)
            f.seek(0)
            f.write(','.join(users))
            f.truncate()
        return True
    except Exception as e:
        print(f"add_user error: {e}")
        return False