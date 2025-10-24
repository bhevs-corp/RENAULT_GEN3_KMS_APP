def is_registered_user(user: str) -> bool:
    try:
        with open('data.txt', 'r', encoding='utf-8') as f:
            users = f.read().strip().split(',')
        return user in users
    except Exception:
        return False

def remove_user(user: str) -> bool:
    try:
        with open('data.txt', 'r+', encoding='utf-8') as f:
            users = f.read().strip().split(',')
            if user not in users:
                return False
            users.remove(user)
            f.seek(0)
            f.write(','.join(users))
            f.truncate()
        return True
    except Exception:
        return False

def add_user(user: str) -> bool:
    try:
        with open('data.txt', 'r+', encoding='utf-8') as f:
            users = f.read().strip().split(',')
            if user in users:
                return False
            users.append(user)
            f.seek(0)
            f.write(','.join(users))
            f.truncate()
        return True
    except Exception:
        return False