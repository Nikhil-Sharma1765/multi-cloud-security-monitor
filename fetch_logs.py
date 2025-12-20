import boto3
import pandas as pd
import json
import gzip
from io import BytesIO


BUCKET_NAME = "nikhil-cloudtrail-logs-eu"
PREFIX = "AWSLogs/"  # CloudTrail stores logs under this prefix

# Initializing boto3 S3 client
s3 = boto3.client("s3")

def list_log_files():
    """List CloudTrail log files in S3 bucket"""
    response = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix=PREFIX)
    files = [obj['Key'] for obj in response.get('Contents', []) if obj['Key'].endswith('.gz')]
    return files

def download_and_parse(file_key):
    """Download and parse a single CloudTrail log file"""
    obj = s3.get_object(Bucket=BUCKET_NAME, Key=file_key)
    with gzip.GzipFile(fileobj=BytesIO(obj['Body'].read())) as f:
        data = json.loads(f.read().decode("utf-8"))
    return data['Records']

def logs_to_dataframe():
    """Convert logs into pandas DataFrame"""
    all_files = list_log_files()
    all_records = []

    for file in all_files[:5]:  # just take first 5 files for demo
        records = download_and_parse(file)
        all_records.extend(records)

    df = pd.DataFrame(all_records)
    return df

if __name__ == "__main__":
    df = logs_to_dataframe()
    print("✅ Sample CloudTrail Logs:")
    print(df[["eventTime", "eventName", "sourceIPAddress", "userAgent"]].head())
