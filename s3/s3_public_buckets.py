import boto3
from botocore.exceptions import ClientError

def check_bucket_public_access(bucket_name):
    """Check if an S3 bucket is public."""
    s3 = boto3.client('s3')
    try:
        # Check bucket ACL
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            if 'AllUsers' in grant['Grantee'].get('URI', '') or 'AuthenticatedUsers' in grant['Grantee'].get('URI', ''):
                return f"Bucket '{bucket_name}' is public via ACL."
        
        # Check bucket policy
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            if policy:
                return f"Bucket '{bucket_name}' has a policy that may allow public access."
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                raise

        # Check public access block
        try:
            public_access_block = s3.get_public_access_block(Bucket=bucket_name)
            if not all(public_access_block['PublicAccessBlockConfiguration'].values()):
                return f"Bucket '{bucket_name}' does not block all public access."
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                raise

        return f"Bucket '{bucket_name}' is not public."
    except ClientError as e:
        return f"Error checking bucket '{bucket_name}': {e}"

def main():
    """Main function to check S3 buckets for public access."""
    s3 = boto3.client('s3')

    try:
        response = s3.list_buckets()
        buckets = [bucket['Name'] for bucket in response['Buckets']]

        print(f"Found {len(buckets)} buckets. Checking for public access...")
        for bucket in buckets:
            result = check_bucket_public_access(bucket)
            print(result)
    except ClientError as e:
        print(f"Error listing buckets: {e}")

if __name__ == "__main__":
    main()
