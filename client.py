#!/usr/bin/env python

import os
import sys
import hashlib
import requests
from getpass import getpass
from dotenv import load_dotenv

def sha1_hash(password):
    """Returns the SHA1 hash of the password in uppercase."""
    return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

def check_pwned(sha1_password):
    """
    Check if the password hash has been pwned.
    Uses the first 5 characters of the SHA1 hash to query the API.
    """
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url)
        if response.status_code != 200:
            print(f"Error: Received status code {response.status_code} from HIBP API.")
            sys.exit(1)
    except Exception as e:
        print("Error occurred during API request:", e)
        sys.exit(1)
    
    # Parse the API response: each line is in the format "hash_suffix:count"
    breach_count = 0
    for line in response.text.splitlines():
        parts = line.split(':')
        if len(parts) != 2:
            continue
        hash_suffix, count = parts
        if hash_suffix.strip().upper() == suffix:
            breach_count = int(count.strip())
            break
    return breach_count

def estimate_strength(password):
    """
    Estimate the password strength based on length and character diversity.
    Returns a score (max 100) and suggestions for improvement.
    """
    score = 0
    suggestions = []
    
    length = len(password)
    if length >= 12:
        score += 40
    elif length >= 8:
        score += 20
    else:
        suggestions.append("Increase password length to at least 12 characters.")
    
    # Check for uppercase, lowercase, digits, and symbols
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    
    if has_upper:
        score += 15
    else:
        suggestions.append("Include uppercase letters.")
    
    if has_lower:
        score += 15
    else:
        suggestions.append("Include lowercase letters.")
    
    if has_digit:
        score += 15
    else:
        suggestions.append("Include digits.")
    
    if has_symbol:
        score += 15
    else:
        suggestions.append("Include symbols.")
    
    # Cap the score at 100
    score = min(score, 100)
    
    return score, suggestions

def main():
    # Load environment variables from config.env
    load_dotenv("config.env")
    hibp_api_key = os.getenv("HIBP_API_KEY")  # Not used for the pwned passwords endpoint
    
    print("=== AxcelT-passintel Password Auditor ===")
    password = getpass("Enter your password: ")
    if not password:
        print("No password entered. Exiting.")
        sys.exit(1)
    
    hashed_password = sha1_hash(password)
    print("Password hashed using SHA1.")
    
    # Check the password against HaveIBeenPwned
    breach_count = check_pwned(hashed_password)
    
    # Estimate the password strength
    strength_score, suggestions = estimate_strength(password)
    
    print("\n--- Password Audit Results ---")
    print(f"Strength Score: {strength_score}/100")
    if breach_count > 0:
        print(f"⚠️  Warning: Your password was found in {breach_count} breach(es)!")
    else:
        print("✅  Good news: Your password was not found in any breaches.")
    
    if suggestions:
        print("\nSuggestions to improve your password:")
        for suggestion in suggestions:
            print(f" - {suggestion}")
    else:
        print("\nYour password meets the basic complexity requirements!")
    
if __name__ == "__main__":
    main()
