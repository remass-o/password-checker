# Password Checker

A Python utility that checks whether your passwords have been exposed in known data breaches using the Pwned Passwords API (https://pwnedpasswords.com/).

## Features

- Check multiple passwords at once from a file
- Privacy-focused: Only first 5 characters of password hash are sent to the API
- Fast and efficient
- Shows number of times each password appeared in breaches
- Clear warnings and helpful feedback

## Installation

1. Clone the repository:
```bash
git clone https://github.com/remass-o/password-checker.git
cd password-checker
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Create a file named `password.txt` with your passwords (one per line):

```bash
python password_checker.py password.txt
```

### Example

**Input file (password.txt):**
```
MyPassword123
SecurePass456
WeakPassword
```

**Output:**
```
'MyPassword123' was found 3 times in breaches. You should definitely change this password!
'SecurePass456' was found 1 time in breaches. You should definitely change this password!
'WeakPassword' was not found in any breaches. This password looks good!
```

## How It Works

1. Reads passwords from a text file
2. Hashes each password using SHA1
3. Sends only the first 5 characters of the hash to the Pwned Passwords API
4. Compares the remaining hash characters with the API response
5. Reports the number of times each password was found in breaches

**Privacy Note:** Your full password hash is never sent to the API. Only the first 5 characters are used for the lookup.

## Requirements

- Python 3.7+
- requests library

## API Reference

- **request_api_data(query_char)**: Fetches hash data from Pwned Passwords API
- **get_password_leaks_count(hashes, hash_to_check)**: Checks if a hash exists in the response
- **pwned_api_check(password)**: Main function to check a single password
- **main(file_path)**: Reads and checks all passwords from a file

## Error Handling

The tool handles common errors gracefully:
- Missing or inaccessible files
- Network connection issues
- Empty password files
- API errors

## Security Disclaimer

This tool uses the public Pwned Passwords API. Never use this tool to check passwords in production systems. Use it only for personal password security audits.

## References

- Have I Been Pwned: https://haveibeenpwned.com/
- Pwned Passwords API: https://pwnedpasswords.com/api/v3
