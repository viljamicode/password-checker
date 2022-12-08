import hashlib
import getpass
import requests


def check_pw(password: str) -> int:
    # Hash the password so we don't send the plaintext password over the internet
    hashed_pw = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # The first 5 characters of the hash are used to search for the password on the "haveibeenpwned.com" API
    pw_first5char = hashed_pw[:5]
    pw_restofpw = hashed_pw[5:]

    # Send a request to the API to check if the password has been leaked
    response = requests.get(
        f"https://api.pwnedpasswords.com/range/{pw_first5char}")

    # If the password has been leaked, the response will contain the last 5 characters of the hash
    # along with the number of times it has been leaked.

    # Print out an error if there is something wrong with the API (for example a typo in the url)
    if response.status_code != 200:
        raise RuntimeError(
            f'Error: {response.status_code}, check API and try again.')

    # Search the response for the password's hash and extract the count
    for line in response.text.splitlines():
        if line.startswith(pw_restofpw):
            count = int(line.split(":")[1])
            return count

    # If the password's hash is not found in the response, it hasn't been leaked
    return 0


def main():
    # Ask the user for their password using the getpass module.
    # NOTE: This gives no visual feedback to the user. The downside of this is that the user might
    # mistype their password, but it is more secure that way.
    password = getpass.getpass(prompt="Enter the password you wish to check: ")

    # Checks how many times the password has been leaked
    count = check_pw(password)
    if count > 0:
        print(
            f"Password has been leaked {count} times, you should change it.")
    else:
        print("Password has NOT been leaked.")


if __name__ == "__main__":
    main()
