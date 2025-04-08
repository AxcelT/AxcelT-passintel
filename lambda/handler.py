import json
import requests

def lambda_handler(event, context):
    """
    AWS Lambda handler that accepts a JSON payload with a SHA1 hash,
    checks the HaveIBeenPwned API for breaches using the k-anonymity method,
    and returns the breach count.
    
    Expected payload:
    {
      "hash": "THE_FULL_SHA1_HASH_OF_THE_PASSWORD"
    }
    """
    
    try:
        body = json.loads(event["body"])
    except (KeyError, TypeError, json.JSONDecodeError):
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Invalid or missing request body."})
        }

    # Validate the incoming payload
    if "hash" not in body:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Missing 'hash' in the request payload."})
        }

    sha1_password = body["hash"]
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    
    # Query HaveIBeenPwned API using the prefix
    hibp_url = f"https://api.pwnedpasswords.com/range/{prefix}"
    
    try:
        response = requests.get(hibp_url)
        if response.status_code != 200:
            return {
                "statusCode": 500,
                "body": json.dumps({"error": f"HIBP API error: {response.status_code}"})
            }
    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": f"Error during request: {str(e)}"})
        }
    
    # Parse the API response to check for a matching suffix
    breach_count = 0
    for line in response.text.splitlines():
        parts = line.split(':')
        if len(parts) != 2:
            continue
        hash_suffix, count = parts
        if hash_suffix.strip().upper() == suffix:
            breach_count = int(count.strip())
            break

    response_body = {
        "pwned": breach_count > 0,
        "breach_count": breach_count
    }
    
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(response_body)
    }
