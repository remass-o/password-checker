import requests  # we could reguests something and we get data back
import hashlib
import sys


def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    # print(res)
    if res.status_code != 200:
        raise RuntimeError(
            f"Error fetching:{res.status_code}, check the api and try again "
        )
    return res


def get_password_leaks_count(
    hashes, hash_to_check
):  # we going to check (hash_to_check) and loop throw all the hashes
    lines = hashes.text.splitlines()
    for line in lines:
        h, count = line.split(":")
        if h == hash_to_check:
            return count

    return 0


def pwned_api_check(password):
    # check password if it exists in API response
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    # print(first5_char, tail)
    # print(response)
    return get_password_leaks_count(response, tail)


def main(file_path):
    with open(file_path, mode="r", encoding="utf-8") as file:
        passwords = [line.strip() for line in file.readlines() if line.strip()]
        for password in passwords:
            count = pwned_api_check(password)
            if count:
                print(
                    f"{password} was found {count} times, you sould probably change your password"
                )
            else:  # if there is no matches then you password is good
                print(f"{password} was not found. you could keep your password!!")


if __name__ == "__main__":
    # sys.exit(main(sys.arg)) # [1:] that mean it except any number of arguments
    file_name = sys.argv[1] if len(sys.argv) > 1 else "password.txt"
    main(file_name)


# it is butter to read from a text file instead of a command line argument
