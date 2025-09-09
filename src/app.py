import boto3
import re
import json
import logging
from urllib.parse import urlparse, parse_qs

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')

# Comprehensive PII regex patterns
EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

# Phone number patterns (various formats)
PHONE_PATTERNS = [
    re.compile(r'\b\d{3}-\d{3}-\d{4}\b'),      # 123-456-7890
    re.compile(r'\(\d{3}\)\s?\d{3}-\d{4}'),    # (123) 456-7890
    re.compile(r'\b\d{3}\s\d{3}\s\d{4}\b'),    # 123 456 7890
    re.compile(r'\b\d{3}\.\d{3}\.\d{4}\b'),    # 123.456.7890
]

# Social Security Numbers
SSN_RE = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')

# Credit card numbers (various formats)
CC_PATTERNS = [
    re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),  # 1234-5678-9012-3456
    re.compile(r'\b\d{13,19}\b'),  # Long number sequences (credit cards)
]

# Bank account numbers (10-17 digits)
ACCOUNT_RE = re.compile(r'\b\d{10,17}\b')

# IP addresses
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Dates of birth (various formats)
DOB_PATTERNS = [
    re.compile(r'\b\d{1,2}/\d{1,2}/\d{4}\b'),  # MM/DD/YYYY
    re.compile(r'\b\d{4}-\d{1,2}-\d{1,2}\b'),  # YYYY-MM-DD
    re.compile(r'\b\d{1,2}-\d{1,2}-\d{4}\b'),  # MM-DD-YYYY
]

def scrub_pii(text: str) -> str:
    """
    Comprehensive PII removal function that handles multiple types of sensitive data
    """
    try:
        logger.info("Applying comprehensive PII removal patterns...")
        original_length = len(text)
        
        # Email addresses
        text = EMAIL_RE.sub('[EMAIL_REMOVED]', text)
        
        # Phone numbers (various formats)
        for pattern in PHONE_PATTERNS:
            text = pattern.sub('[PHONE_REMOVED]', text)
        
        # Social Security Numbers
        text = SSN_RE.sub('[SSN_REMOVED]', text)
        
        # Credit card numbers (various formats)
        for pattern in CC_PATTERNS:
            text = pattern.sub('[CARD_REMOVED]', text)
        
        # Bank account numbers (10-17 digits)
        # Note: This is more selective to avoid false positives
        # Only replace if it's not already part of a credit card pattern
        if not any(pattern.search(text) for pattern in CC_PATTERNS):
            text = ACCOUNT_RE.sub('[ACCOUNT_REMOVED]', text)
        
        # IP addresses
        text = IP_RE.sub('[IP_REMOVED]', text)
        
        # Dates of birth (various formats)
        for pattern in DOB_PATTERNS:
            text = pattern.sub('[DOB_REMOVED]', text)
        
        processed_length = len(text)
        logger.info(f"PII removal complete. Length changed from {original_length} to {processed_length}")
        
        return text
        
    except Exception as e:
        logger.error(f"Error in PII removal: {str(e)}")
        # Return original text if processing fails
        return text

def lambda_handler(event, context):
    try:
        logger.info(f"Received event: {json.dumps(event)}")
        
        # Get object context
        object_context = event["getObjectContext"]
        request_route = object_context["outputRoute"]
        request_token = object_context["outputToken"]
        s3_url = object_context["inputS3Url"]
        
        logger.info(f"S3 URL: {s3_url}")
        
        # Parse the pre-signed URL
        parsed_url = urlparse(s3_url)
        
        # Extract bucket name from hostname
        # Format: raw-data-access-point-359110058371.s3-accesspoint.us-east-1.amazonaws.com
        hostname_parts = parsed_url.hostname.split('.')
        bucket_name = hostname_parts[0]  # This will be the access point name
        
        # Extract object key from path
        object_key = parsed_url.path.lstrip('/')
        
        logger.info(f"Parsed - Bucket/Access Point: {bucket_name}, Key: {object_key}")
        
        # Since this is coming from an access point, we need to use the supporting access point ARN
        supporting_access_point_arn = event["configuration"]["supportingAccessPointArn"]
        logger.info(f"Supporting Access Point ARN: {supporting_access_point_arn}")
        
        # Get object from S3 using the supporting access point
        # Extract the access point name from the ARN
        access_point_name = supporting_access_point_arn.split('/')[-1]
        
        response = s3.get_object(
            Bucket=supporting_access_point_arn,  # Use the full ARN
            Key=object_key
        )
        
        # Handle different content types
        body = response["Body"].read()
        
        # Try to decode as text
        try:
            if isinstance(body, bytes):
                try:
                    text_content = body.decode('utf-8')
                except UnicodeDecodeError:
                    # Try other common encodings
                    for encoding in ['latin-1', 'ascii', 'cp1252']:
                        try:
                            text_content = body.decode(encoding)
                            break
                        except UnicodeDecodeError:
                            continue
                    else:
                        logger.warning("Could not decode content as text, returning as-is")
                        # For binary files, return as-is
                        s3.write_get_object_response(
                            Body=body,
                            RequestRoute=request_route,
                            RequestToken=request_token,
                            ContentType=response.get('ContentType', 'application/octet-stream')
                        )
                        return {"status_code": 200}
            else:
                text_content = str(body)
                
        except Exception as decode_error:
            logger.warning(f"Could not decode content: {decode_error}")
            # Return original content if we can't decode it
            s3.write_get_object_response(
                Body=body,
                RequestRoute=request_route,
                RequestToken=request_token,
                ContentType=response.get('ContentType', 'application/octet-stream')
            )
            return {"status_code": 200}
        
        logger.info(f"Original body length: {len(text_content)}")
        logger.info(f"Original content preview: {text_content[:100]}...")
        
        # Scrub PII using comprehensive patterns
        cleaned_body = scrub_pii(text_content)
        
        logger.info(f"Cleaned body length: {len(cleaned_body)}")
        logger.info(f"Cleaned content preview: {cleaned_body[:100]}...")
        
        # Send back response using s3 client
        s3.write_get_object_response(
            Body=cleaned_body.encode("utf-8"),
            RequestRoute=request_route,
            RequestToken=request_token,
            ContentType=response.get('ContentType', 'text/plain'),
            ContentLength=len(cleaned_body.encode("utf-8")),
            ETag=response.get('ETag'),
            LastModified=response.get('LastModified'),
            Metadata=response.get('Metadata', {})
        )
        
        logger.info("Successfully sent response")
        return {"status_code": 200}
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        logger.error(f"Event: {json.dumps(event)}")
        
        # Send error response back to S3 Object Lambda
        try:
            s3.write_get_object_response(
                RequestRoute=request_route,
                RequestToken=request_token,
                StatusCode=500,
                ErrorCode="InternalError",
                ErrorMessage=str(e)
            )
        except Exception as response_error:
            logger.error(f"Failed to send error response: {str(response_error)}")
        
        raise e
