import boto3
import json

# AWS Account mapping
account_names = {
    '774337928902': 'Sandbox',
    '452625356000': 'Devx',
    '390572758820': 'Fintech',
    '924334593285': 'Identity',
    '662769906594': 'Prod',
    '256199385484': 'Data'
}

# Expanded list of sensitive permissions across various AWS services
SENSITIVE_PERMISSIONS = [
    # IAM Permissions
    'iam:CreateAccessKey', 'iam:CreateUser', 'iam:CreateRole', 'iam:CreatePolicy', 
    'iam:AttachUserPolicy', 'iam:AttachGroupPolicy', 'iam:AttachRolePolicy', 
    'iam:PutUserPolicy', 'iam:PutGroupPolicy', 'iam:PutRolePolicy', 'iam:DeleteUser',
    'iam:DeleteRole', 'iam:DeletePolicy', 'iam:PassRole', 'iam:UpdateAssumeRolePolicy', 
    'iam:AddUserToGroup', 'iam:RemoveUserFromGroup', 'iam:AttachRolePolicy',

    # EC2 Permissions
    'ec2:CreateSecurityGroup', 'ec2:DeleteSecurityGroup', 'ec2:AuthorizeSecurityGroupIngress', 
    'ec2:RevokeSecurityGroupIngress', 'ec2:RunInstances', 'ec2:TerminateInstances', 
    'ec2:CreateKeyPair', 'ec2:DeleteKeyPair', 'ec2:ModifyInstanceAttribute', 'ec2:DescribeInstances',
    'ec2:ModifyNetworkInterfaceAttribute', 'ec2:AssociateIamInstanceProfile',

    # Lambda Permissions
    'lambda:CreateFunction', 'lambda:DeleteFunction', 'lambda:InvokeFunction', 
    'lambda:AddPermission', 'lambda:RemovePermission', 'lambda:UpdateFunctionCode', 
    'lambda:UpdateFunctionConfiguration',

    # S3 Permissions
    's3:CreateBucket', 's3:DeleteBucket', 's3:PutBucketPolicy', 's3:DeleteBucketPolicy', 
    's3:PutObject', 's3:DeleteObject', 's3:ListBucket', 's3:GetBucketAcl', 
    's3:PutBucketAcl', 's3:PutBucketWebsite',

    # STS Permissions
    'sts:AssumeRole', 'sts:AssumeRoleWithSAML', 'sts:AssumeRoleWithWebIdentity',

    # CloudFormation Permissions
    'cloudformation:CreateStack', 'cloudformation:UpdateStack', 'cloudformation:DeleteStack', 
    'cloudformation:DescribeStacks', 'cloudformation:DescribeStackResources',
    'cloudformation:CreateChangeSet', 'cloudformation:ExecuteChangeSet',

    # Other Permissions
    'route53:ChangeResourceRecordSets', 'route53:CreateHealthCheck', 'route53:DeleteHealthCheck', 
    'route53:CreateHostedZone', 'route53:DeleteHostedZone', 'route53:ListResourceRecordSets',
]

# Initialize a session using boto3
session = boto3.Session()
iam_client = session.client('iam')
ec2_client = session.client('ec2')
lambda_client = session.client('lambda')
s3_client = session.client('s3')
sts_client = session.client('sts')
cloudformation_client = session.client('cloudformation')
route53_client = session.client('route53')

def get_current_account_name():
    """Get the current AWS account name using sts.get_caller_identity."""
    response = sts_client.get_caller_identity()
    account_id = response['Account']
    account_name = account_names.get(account_id, 'Unknown')
    return account_name, account_id

def get_all_policies():
    """Retrieve all IAM policies in the account."""
    paginator = iam_client.get_paginator('list_policies')
    policies = []
    for page in paginator.paginate(Scope='Local'):
        policies.extend(page['Policies'])
    return policies

def get_policy_permissions(policy_arn):
    """Retrieve the permissions in a given policy."""
    policy_versions = iam_client.list_policy_versions(PolicyArn=policy_arn)
    for version in policy_versions['Versions']:
        if version['IsDefaultVersion']:
            policy_document = iam_client.get_policy_version(
                PolicyArn=policy_arn, 
                VersionId=version['VersionId']
            )
            return policy_document['PolicyVersion']['Document']['Statement']
    return []

def check_sensitive_permissions_in_policy(statements):
    """Check if any of the permissions in a policy are sensitive."""
    sensitive_permissions = set()  # Use a set to avoid duplication
    for statement in statements:
        if statement.get('Effect') == 'Allow':
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if action in SENSITIVE_PERMISSIONS:
                    sensitive_permissions.add(action)
    return sensitive_permissions

def check_user_roles_and_policies(account_name, account_id):
    """Check the policies attached to IAM users, groups, and roles for sensitive permissions."""
    results = []
    
    # Check roles
    roles = iam_client.list_roles()
    for role in roles['Roles']:
        role_name = role['RoleName']
        print(f"\nChecking Role: {role_name}")
        sensitive_permissions = set()
        
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
        for policy in attached_policies['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            statements = get_policy_permissions(policy_arn)
            sensitive_permissions.update(check_sensitive_permissions_in_policy(statements))
        
        if sensitive_permissions:
            results.append({
                "account_name": account_name,
                "account_id": account_id,
                "resource_type": "Role",
                "resource_name": role_name,
                "sensitive_permissions": list(sensitive_permissions)
            })
            print(f"Sensitive Permissions for Role '{role_name}': {', '.join(sensitive_permissions)}")
    
    # Check users
    users = iam_client.list_users()
    for user in users['Users']:
        user_name = user['UserName']
        print(f"\nChecking User: {user_name}")
        sensitive_permissions = set()
        
        attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
        for policy in attached_policies['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            statements = get_policy_permissions(policy_arn)
            sensitive_permissions.update(check_sensitive_permissions_in_policy(statements))
        
        if sensitive_permissions:
            results.append({
                "account_name": account_name,
                "account_id": account_id,
                "resource_type": "User",
                "resource_name": user_name,
                "sensitive_permissions": list(sensitive_permissions)
            })
            print(f"Sensitive Permissions for User '{user_name}': {', '.join(sensitive_permissions)}")
    
    # Check groups
    groups = iam_client.list_groups()
    for group in groups['Groups']:
        group_name = group['GroupName']
        print(f"\nChecking Group: {group_name}")
        sensitive_permissions = set()
        
        attached_policies = iam_client.list_attached_group_policies(GroupName=group_name)
        for policy in attached_policies['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            statements = get_policy_permissions(policy_arn)
            sensitive_permissions.update(check_sensitive_permissions_in_policy(statements))
        
        if sensitive_permissions:
            results.append({
                "account_name": account_name,
                "account_id": account_id,
                "resource_type": "Group",
                "resource_name": group_name,
                "sensitive_permissions": list(sensitive_permissions)
            })
            print(f"Sensitive Permissions for Group: {', '.join(sensitive_permissions)}")

    return results

def write_to_file(account_name, account_id, results):
    """Write the findings to a JSON file."""
    file_name = f"sensitive_permissions_{account_name}_{account_id}.json"
    with open(file_name, 'w') as file:
        json.dump(results, file, indent=4)

if __name__ == "__main__":
    # Get current account name and ID
    account_name, account_id = get_current_account_name()
    
    print(f"\nStarting check for account {account_name} ({account_id})...\n")
    sensitive_permissions_results = check_user_roles_and_policies(account_name, account_id)
    if sensitive_permissions_results:
        write_to_file(account_name, account_id, sensitive_permissions_results)
    else:
        print(f"No sensitive permissions found for account {account_name} ({account_id}).\n")
    print("\nSensitive permissions check complete.")
