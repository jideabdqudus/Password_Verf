import requests
import hashlib
import sys


def request_api_data(query):
    url = f"https://api.pwnedpasswords.com/range/{query}"
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f"Error fetching: {response.status_code}, check the API")
    return response


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            print(f"This password has been pwned {count} time")
            return count
    print(f"This password is safe")
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5char)
    print(response)
    return get_password_leaks_count(hashes=response, hash_to_check=tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"The password {password} was pwned {count} times")
        else:
            print(f"You are all good, the password {password} was not found")
    return "done"


if __name__ == "__main__":
    pwned_api_check("password123")
    sys.exit(main(sys.argv[1:]))
