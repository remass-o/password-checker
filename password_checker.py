"""
Password Security Checker using Pwned Passwords API.

This module checks if passwords have been exposed in known data breaches
using the Have I Been Pwned API (https://pwnedpasswords.com/).
"""

import requests
import hashlib
import sys
from typing import Union


def request_api_data(query_char: str) -> requests.Response:
    """
    Fetch password hash data from Pwned Passwords API.
    
    Args:
        query_char (str): First 5 characters of SHA1 hash
        
    Returns:
        requests.Response: API response object
        
    Raises:
        RuntimeError: If API request fails
    """
    url = "https://api.pwnedpasswords.com/range/" + query_char
    try:
        res = requests.get(url, timeout=5)
        if res.status_code != 200:
            raise RuntimeError(
                f"Error fetching from API: {res.status_code}. "
                "Please check the API and try again."
            )
        return res
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Network error while connecting to API: {e}")


def get_password_leaks_count(hashes: requests.Response, hash_to_check: str) -> int:
    """
    Check if password hash exists in the leaked hashes list.
    
    Args:
        hashes (requests.Response): API response containing leaked hashes
        hash_to_check (str): Hash suffix to search for
        
    Returns:
        int: Number of times password appeared in breaches, 0 if not found
    """
    lines = hashes.text.splitlines()
    for line in lines:
        h, count = line.split(":")
        if h == hash_to_check:
            return int(count)
    
    return 0


def pwned_api_check(password: str) -> int:
    """
    Check if a password has been exposed in known data breaches.
    
    Uses SHA1 hashing and queries the Pwned Passwords API
    with only the first 5 characters for privacy.
    
    Args:
        password (str): Password to check
        
    Returns:
        int: Number of times password was found in breaches
    """
    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char = sha1_password[:5]
    tail = sha1_password[5:]
    
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(file_path: str) -> None:
    """
    Read passwords from file and check each one against Pwned Passwords API.
    
    Args:
        file_path (str): Path to text file containing passwords (one per line)
        
    Raises:
        FileNotFoundError: If the specified file doesn't exist
    """
    try:
        with open(file_path, mode="r", encoding="utf-8") as file:
            passwords = [line.strip() for line in file.readlines() if line.strip()]
            
            if not passwords:
                print(f"Warning: No passwords found in {file_path}")
                return
            
            for password in passwords:
                try:
                    count = pwned_api_check(password)
                    if count:
                        print(
                            f"'{password}' was found {count} times in breaches. "
                            "You should definitely change this password!"
                        )
                    else:
                        print(
                            f"'{password}' was not found in any breaches. "
                            "This password looks good!"
                        )
                except RuntimeError as e:
                    print(f"Error checking '{password}': {e}")
                    
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    file_name = sys.argv[1] if len(sys.argv) > 1 else "password.txt"
    main(file_name)
