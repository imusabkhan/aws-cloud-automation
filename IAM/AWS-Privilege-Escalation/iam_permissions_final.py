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

# Define sensitive permissions for each category

# Privilege escalation permissions
PRIVILEGE_ESCALATION_PERMISSIONS = [
    # IAM Permissions
    'iam:PassRole', 'iam:AssumeRole', 'iam:AttachRolePolicy', 'iam:AttachUserPolicy', 'iam:AttachGroupPolicy',
    'iam:AddUserToGroup', 'iam:RemoveUserFromGroup', 'iam:PutUserPolicy', 'iam:PutGroupPolicy', 'iam:PutRolePolicy',
    'iam:UpdateAssumeRolePolicy', 'iam:CreatePolicy', 'iam:CreateRole', 'iam:DeleteRole', 'iam:CreateUser', 
    'iam:DeleteUser', 'iam:CreateAccessKey', 'iam:UpdateAccessKey', 'iam:UploadSSHPublicKey', 'iam:deactivate-mfa-device', 'iam:resync-mfa-device',

    # EC2 Permissions
    'ec2:AssociateIamInstanceProfile', 'ec2:ModifyInstanceAttribute', 'ec2:RunInstances', 'ec2:TerminateInstances',
    'ec2:CreateSecurityGroup', 'ec2:DeleteSecurityGroup', 'ec2:AuthorizeSecurityGroupIngress', 'ec2:AuthorizeSecurityGroupEgress',
    'ec2:RevokeSecurityGroupIngress', 'ec2:RevokeSecurityGroupEgress',

    # Lambda Permissions
    'lambda:AddPermission', 'lambda:RemovePermission', 'lambda:CreateFunction', 'lambda:DeleteFunction',
    'lambda:UpdateFunctionCode', 'lambda:UpdateFunctionConfiguration',

    # STS Permissions
    'sts:AssumeRole',

    # CloudFormation Permissions
    'cloudformation:CreateStack', 'cloudformation:UpdateStack', 'cloudformation:DeleteStack', 'cloudformation:CreateChangeSet', 
    'cloudformation:ExecuteChangeSet', 'cloudformation:UpdateStackSet', 'cloudformation:DeleteStackSet',

    # S3 Permissions
    's3:PutBucketAcl', 's3:PutBucketPolicy', 's3:PutObject', 's3:DeleteObject', 's3:CreateBucket', 's3:DeleteBucket',
    's3:PutBucketLogging', 's3:PutBucketWebsite', 's3:PutBucketVersioning', 's3:PutBucketLifecycle', 's3:PutBucketNotification',

    # Route53 Permissions
    'route53:ChangeResourceRecordSets', 'route53:CreateHealthCheck', 'route53:DeleteHealthCheck', 'route53:CreateHostedZone', 
    'route53:DeleteHostedZone',

    # IAM Group Permissions
    'iam:AttachGroupPolicy', 'iam:PutGroupPolicy',

    # SSM Permissions (For Privilege Escalation via EC2)
    'ssm:StartSession', 'ssm:SendCommand', 'ssm:PutParameter', 'ssm:GetParameters',

    # Secrets Manager Permissions (Escalation Potential via Storing Secrets)
    'secretsmanager:GetSecretValue', 'secretsmanager:PutSecretValue', 'secretsmanager:DeleteSecret', 'secretsmanager:CreateSecret',

    # Elastic Load Balancing Permissions
    'elbv2:CreateTargetGroup', 'elbv2:DeleteTargetGroup', 'elbv2:ModifyTargetGroupAttributes', 'elbv2:RegisterTargets',
    'elbv2:DeregisterTargets',

    # KMS Permissions (Key Management)
    'kms:CreateKey', 'kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey', 'kms:PutKeyPolicy', 'kms:DeleteKey',

    # SQS Permissions
    'sqs:SendMessage', 'sqs:ReceiveMessage', 'sqs:DeleteMessage', 'sqs:CreateQueue', 'sqs:DeleteQueue',

    # SNS Permissions
    'sns:Publish', 'sns:Subscribe', 'sns:Unsubscribe', 'sns:CreateTopic', 'sns:DeleteTopic',

    # ECR Permissions (Escalation via Container Images)
    'ecr:BatchGetImage', 'ecr:BatchCheckLayerAvailability', 'ecr:GetAuthorizationToken', 'ecr:PutImage', 'ecr:DeleteRepository',

    # CodeBuild Permissions (Escalation via Build Projects)
    'codebuild:StartBuild', 'codebuild:StopBuild', 'codebuild:BatchGetBuilds', 'codebuild:CreateProject', 'codebuild:DeleteProject',

    # CodeDeploy Permissions
    'codedeploy:CreateDeployment', 'codedeploy:DeleteDeployment', 'codedeploy:GetDeployment', 'codedeploy:StopDeployment',

    # Elastic Beanstalk Permissions
    'elasticbeanstalk:CreateApplication', 'elasticbeanstalk:DeleteApplication', 'elasticbeanstalk:CreateEnvironment',
    'elasticbeanstalk:TerminateEnvironment', 'elasticbeanstalk:UpdateEnvironment',

    # CloudWatch Permissions
    'cloudwatch:PutMetricData', 'cloudwatch:PutDashboard', 'cloudwatch:SetAlarmState', 'cloudwatch:PutAnomalyDetector',

    # VPC Permissions
    'ec2:CreateVpc', 'ec2:DeleteVpc', 'ec2:ModifyVpcAttribute', 'ec2:CreateSubnet', 'ec2:DeleteSubnet', 'ec2:AssociateRouteTable', 
    'ec2:DisassociateRouteTable', 'ec2:CreateRoute', 'ec2:DeleteRoute',

    # RDS Permissions
    'rds:CreateDBInstance', 'rds:DeleteDBInstance', 'rds:ModifyDBInstance', 'rds:CreateDBCluster', 'rds:DeleteDBCluster',
    'rds:AddRoleToDBCluster', 'rds:RemoveRoleFromDBCluster',

    # DynamoDB Permissions
    'dynamodb:CreateTable', 'dynamodb:DeleteTable', 'dynamodb:UpdateTable', 'dynamodb:PutItem', 'dynamodb:BatchWriteItem',
    'dynamodb:UpdateItem', 'dynamodb:DeleteItem',

    # Redshift Permissions
    'redshift:CreateCluster', 'redshift:DeleteCluster', 'redshift:ModifyCluster', 'redshift:CreateClusterSnapshot',
    'redshift:DeleteClusterSnapshot',

    # Kinesis Permissions
    'kinesis:PutRecord', 'kinesis:PutRecords', 'kinesis:CreateStream', 'kinesis:DeleteStream'
]

# Destructive actions permissions
DESTRUCTIVE_ACTIONS_PERMISSIONS = [
    's3:DeleteBucket', 's3:DeleteObject', 'ec2:TerminateInstances', 
    'cloudformation:DeleteStack', 'route53:DeleteHostedZone', 
    'iam:DeleteUser', 'iam:DeleteRole', 'iam:DeletePolicy', 
    'cloudformation:DeleteChangeSet'
]

# Initialize a session using boto3
session = boto3.Session()
iam_client = session.client('iam')
sts_client = session.client('sts')
# ec2_client = session.client('ec2')
# lambda_client = session.client('lambda')
# s3_client = session.client('s3')
# cloudformation_client = session.client('cloudformation')
# route53_client = session.client('route53')

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
    privilege_escalation = set()
    destructive_actions = set()

    for statement in statements:
        if statement.get('Effect') == 'Allow':
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if action in PRIVILEGE_ESCALATION_PERMISSIONS:
                    privilege_escalation.add(action)
                elif action in DESTRUCTIVE_ACTIONS_PERMISSIONS:
                    destructive_actions.add(action)
    
    return privilege_escalation, destructive_actions

def check_user_roles_and_policies(account_name, account_id):
    """Check the policies attached to IAM users, groups, and roles for sensitive permissions."""
    results = []
    
    # Check roles
    roles = iam_client.list_roles()
    for role in roles['Roles']:
        role_name = role['RoleName']
        print(f"\nChecking Role: {role_name}")
        privilege_escalation = set()
        destructive_actions = set()
        
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
        for policy in attached_policies['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            statements = get_policy_permissions(policy_arn)
            p_e, d_a = check_sensitive_permissions_in_policy(statements)
            privilege_escalation.update(p_e)
            destructive_actions.update(d_a)
        
        if privilege_escalation or destructive_actions:
            results.append({
                "account_name": account_name,
                "account_id": account_id,
                "resource_type": "Role",
                "resource_name": role_name,
                "privilege_escalation": list(privilege_escalation),
                "destructive_actions": list(destructive_actions)
            })
            print(f"Privilege Escalation Permissions: {', '.join(privilege_escalation)}")
            print(f"Destructive Actions: {', '.join(destructive_actions)}")
    
    # Check users
    users = iam_client.list_users()
    for user in users['Users']:
        user_name = user['UserName']
        print(f"\nChecking User: {user_name}")
        privilege_escalation = set()
        destructive_actions = set()
        
        attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
        for policy in attached_policies['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            statements = get_policy_permissions(policy_arn)
            p_e, d_a = check_sensitive_permissions_in_policy(statements)
            privilege_escalation.update(p_e)
            destructive_actions.update(d_a)
        
        if privilege_escalation or destructive_actions:
            results.append({
                "account_name": account_name,
                "account_id": account_id,
                "resource_type": "User",
                "resource_name": user_name,
                "privilege_escalation": list(privilege_escalation),
                "destructive_actions": list(destructive_actions)
            })
            print(f"Privilege Escalation Permissions for User '{user_name}': {', '.join(privilege_escalation)}")
            print(f"Destructive Actions for User '{user_name}': {', '.join(destructive_actions)}")
    
    # Check groups
    groups = iam_client.list_groups()
    for group in groups['Groups']:
        group_name = group['GroupName']
        print(f"\nChecking Group: {group_name}")
        privilege_escalation = set()
        destructive_actions = set()
        
        attached_policies = iam_client.list_attached_group_policies(GroupName=group_name)
        for policy in attached_policies['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            statements = get_policy_permissions(policy_arn)
            p_e, d_a = check_sensitive_permissions_in_policy(statements)
            privilege_escalation.update(p_e)
            destructive_actions.update(d_a)
        
        if privilege_escalation or destructive_actions:
            results.append({
                "account_name": account_name,
                "account_id": account_id,
                "resource_type": "Group",
                "resource_name": group_name,
                "privilege_escalation": list(privilege_escalation),
                "destructive_actions": list(destructive_actions)
            })
            print(f"Privilege Escalation Permissions for Group '{group_name}': {', '.join(privilege_escalation)}")
            print(f"Destructive Actions for Group '{group_name}': {', '.join(destructive_actions)}")

    return results

def write_to_file(account_name, account_id, results):
    """Write the findings to a JSON file."""
    file_name = f"sensitive_permissions_{account_name}.json"
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
