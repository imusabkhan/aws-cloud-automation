import boto3
import time
import copy
import json
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize a Boto3 session and IAM client
session = boto3.Session(region_name='ap-southeast-1')
iam_client = session.client('iam')

# AWS Account mapping
account_names = {
    '000000000000': 'Musab'
}

# Function to get the account name based on the account ID
def get_account_name(accountId):
    return account_names.get(accountId, 'Unknown')

# Function to list all IAM roles in the account
def list_all_roles():
    roles = []
    paginator = iam_client.get_paginator('list_roles')
    for page in paginator.paginate():
        roles.extend(page['Roles'])
    return roles

# Function to retrieve IAM role information
def get_role(role_name):
    try:
        response = iam_client.get_role(RoleName=role_name)
        return response['Role']
    except iam_client.exceptions.NoSuchEntityException:
        print(f"Role '{role_name}' does not exist.")
        return None

# Function to retrieve inline and attached policies for the role
def get_role_policies(role_name):
    policies = {'InlinePolicies': [], 'AttachedPolicies': []}

    # Get inline policies
    inline_policies = iam_client.list_role_policies(RoleName=role_name)
    policies['InlinePolicies'] = inline_policies['PolicyNames']

    # Get attached managed policies
    attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
    for policy in attached_policies['AttachedPolicies']:
        policies['AttachedPolicies'].append(policy['PolicyArn'])

    return policies

# Function to retrieve the policy document for a managed policy
def get_policy_document(policy_arn):
    policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
    policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)
    return policy_document['PolicyVersion']['Document']

# Function to retrieve the inline policy document
def get_inline_policy_document(role_name, policy_name):
    return iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']

# Function to retrieve the last accessed details for a service based on the role's ARN
def get_last_accessed_details(role_arn):
    try:
        # Generate last accessed details for the role
        response = iam_client.generate_service_last_accessed_details(
            Arn=role_arn,
            Granularity='ACTION_LEVEL'
        )

        job_id = response['JobId']
        # Wait for the job to complete and get the results
        while True:
            response = iam_client.get_service_last_accessed_details(JobId=job_id)
            if response['JobStatus'] == 'COMPLETED':
                return response['ServicesLastAccessed']
            elif response['JobStatus'] in ['FAILED', 'CANCELLED']:
                print(f"Job failed with status: {response['JobStatus']}")
                return []
            time.sleep(1)  # Avoid excessive polling
    except Exception as e:
        print(f"Error retrieving last accessed details: {e}")
        return []

# Function to analyze the last accessed details for the role and identify permissions used in the last 90 days
def analyze_role_permissions(role_name):
    role = get_role(role_name)
    if not role:
        return

    role_arn = role['Arn']
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    print(f"Processing role: {role_name}")

    # Get assigned permissions for the role (both inline and attached permissions through AWS)
    permissions = get_role_policies(role_name)

    # Initialize structures to hold granted and used permissions
    granted_permissions = {}
    used_permissions = {}
    unused_permissions = {}

    # Get inline permissions
    if permissions['InlinePolicies']:
        for policy_name in permissions['InlinePolicies']:
            inline_policy_document = get_inline_policy_document(role_name, policy_name)
            if 'Statement' in inline_policy_document:
                for statement in inline_policy_document['Statement']:
                    if 'Action' in statement:
                        actions = statement['Action']
                        if isinstance(actions, str):
                            actions = [actions]  # Ensure actions are in a list
                        for action in actions:
                            service = action.split(':')[0].lower()
                            action = f"{service}:{action.split(':')[1]}" if action != "*" else "*:*"
                            if service not in granted_permissions:
                                granted_permissions[service] = []
                            granted_permissions[service].append(action)

    # Get managed permissions
    for policy_arn in permissions['AttachedPolicies']:
        policy_document = get_policy_document(policy_arn)
        if 'Statement' in policy_document:
            for statement in policy_document['Statement']:
                if 'Action' in statement:
                    actions = statement['Action']
                    if isinstance(actions, str):
                        actions = [actions]  # Ensure actions are in a list
                    for action in actions:
                        service = action.split(':')[0].lower()
                        action = f"{service}:{action.split(':')[1]}" if action != "*" else "*:*"
                        if service not in granted_permissions:
                            granted_permissions[service] = []
                        granted_permissions[service].append(action)

    # Setting unused permissions as granted permissions
    unused_permissions = copy.deepcopy(granted_permissions)

    # Retrieve the last accessed details for this role
    last_accessed_details = get_last_accessed_details(role_arn)

    # Analyze last accessed details for specific services within the last 90 days
    for service in last_accessed_details:
        service_name = service['ServiceNamespace'].lower()
        last_accessed_date = service.get('LastAuthenticated')
        tracked_actions = service.get('TrackedActionsLastAccessed', [])
        tracked_authenticated = service.get('TotalAuthenticatedEntities')

        # Initialize used permissions for this service
        used_permissions[service_name] = set()  # Use a set to avoid duplicates

        if tracked_authenticated >= 1:
            if last_accessed_date > thirty_days_ago:
                if tracked_actions:
                    for action_detail in tracked_actions:
                        action_name = f"{service_name}:{action_detail['ActionName']}"
                        lastAccessFlag = 0
                        if "LastAccessedTime" in action_detail:
                            action_accessed_date = action_detail.get('LastAccessedTime')
                            if action_accessed_date < thirty_days_ago:
                                lastAccessFlag = 1
                        if service_name in unused_permissions:
                            while action_name in unused_permissions[service_name]:
                                unused_permissions[service_name].remove(action_name)
                        used_permissions[service_name].add(action_name)  # Add action to used permissions
                else:
                    used_permissions[service_name].add("action not tracked but used")
                    if service_name in unused_permissions:
                        del unused_permissions[service_name]

    # Prepare output for JSON
    output = {
        'RoleName': role_name,
        'GrantedPermissions': {service: list(set(actions)) for service, actions in granted_permissions.items()},
        'UsedPermissions': {service: list(set(actions)) for service, actions in used_permissions.items() if actions},
        'UnusedPermissions': {service: list(set(actions)) for service, actions in unused_permissions.items() if actions}
    }

    return output  # Return the output for all roles

# Function to analyze permissions in parallel using threads
def analyze_permissions_in_parallel(roles):
    outputs = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_role = {executor.submit(analyze_role_permissions, role['RoleName']): role for role in roles}
        for future in as_completed(future_to_role):
            role_output = future.result()
            if role_output:  # Ensure the role_output is not None
                outputs.append(role_output)
    return outputs

# Main function to execute the review for a specific IAM role
def main():
    # Get the account ID from the STS client
    accountId = session.client('sts').get_caller_identity()['Account']
    account_name = get_account_name(accountId)

    roles = list_all_roles()
    all_outputs = analyze_permissions_in_parallel(roles)

    # Get the current date for the filename
    current_date = datetime.now().strftime('%Y-%m-%d')
    # Save the output to a JSON file with account name and current date
    output_filename = f"iam_unused_permissions_{account_name}_{current_date}.json"
    with open(output_filename, "w") as json_file:
        json.dump(all_outputs, json_file, indent=4)  # Save as an array of role outputs

if __name__ == "__main__":
    main()
