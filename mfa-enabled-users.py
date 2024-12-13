import boto3
from botocore.exceptions import ClientError

def get_iam_client(profile=None):
    """
    Returns a boto3 IAM client.
    :param profile: The AWS CLI profile to use (optional).
    """
    session = boto3.Session(profile_name=profile)
    return session.client('iam')

def check_mfa_for_user(iam_client, username):
    """
    Checks if MFA is enabled for a specific IAM user.
    :param iam_client: The boto3 IAM client.
    :param username: The IAM username.
    :return: True if MFA is enabled, False otherwise.
    """
    try:
        mfa_devices = iam_client.list_mfa_devices(UserName=username)
        return len(mfa_devices['MFADevices']) > 0
    except ClientError as e:
        print(f"Error checking MFA for user {username}: {e}")
        return False

def list_users_without_mfa(iam_client):
    """
    Lists IAM users who do not have MFA enabled.
    :param iam_client: The boto3 IAM client.
    :return: A list of IAM usernames without MFA enabled.
    """
    users_without_mfa = []
    try:
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                if not check_mfa_for_user(iam_client, username):
                    users_without_mfa.append(username)
    except ClientError as e:
        print(f"Error listing users: {e}")
    return users_without_mfa

def main():
    # Specify your AWS profiles here
    aws_profiles = ['account1', 'account2', 'account3', 'account4', 'account5']

    for profile in aws_profiles:
        print(f"Checking MFA status in account: {profile}")
        iam_client = get_iam_client(profile)
        users_without_mfa = list_users_without_mfa(iam_client)

        if users_without_mfa:
            print(f"Users without MFA in account {profile}: {users_without_mfa}")
        else:
            print(f"All users have MFA enabled in account {profile}")

if __name__ == "__main__":
    main()

