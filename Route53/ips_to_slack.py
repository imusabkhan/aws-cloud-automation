import boto3
import ipaddress
import requests

# Define the account mapping
# AWS Account mapping
account_names = {
    '000000000000': 'Musab'
}

SLACK_WEBHOOK_URL = 'https://hooks.slack.com/'  # Replace with your Slack webhook URL

def get_route53_records():
    """Fetch all DNS records from Route53."""
    route53_client = boto3.client('route53')
    records = []

    # Get all hosted zones
    hosted_zones = route53_client.list_hosted_zones()
    for zone in hosted_zones['HostedZones']:
        zone_id = zone['Id']
        zone_id = zone_id.split('/')[-1]  # Extract zone ID
        paginator = route53_client.get_paginator('list_resource_record_sets')

        # Fetch all record sets for the hosted zone
        for page in paginator.paginate(HostedZoneId=zone_id):
            records.extend(page['ResourceRecordSets'])

    return records

def get_elastic_ips(region='ap-southeast-1'):
    """Fetch all allocated Elastic IPs in the specified region."""
    session = boto3.Session()
    elastic_ips = set()

    ec2_client = session.client('ec2', region_name=region)
    try:
        response = ec2_client.describe_addresses()
        for address in response['Addresses']:
            elastic_ips.add(address['PublicIp'])
    except Exception as e:
        print(f"Error fetching EIPs in region {region}: {e}")

    return elastic_ips

def get_aws_account_name():
    """Fetch the AWS account name using the account ID mapping."""
    sts_client = boto3.client('sts')
    response = sts_client.get_caller_identity()
    account_id = response['Account']
    
    # Use the account ID to get the account name from the mapping
    return account_names.get(account_id, "Unknown Account")

def is_private_ip(ip):
    """Check if the given IP is in a private range."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Return True if the IP is in a private range
        return ip_obj.is_private
    except ValueError:
        return False  # Invalid IP format

def send_to_slack(dangling_ips):
    """Send the dangling IP information to Slack."""
    if not dangling_ips:
        return  # Don't send empty data

    slack_message = {
        "text": "Dangling IPs found in AWS environment:\n"
    }

    # Format the message to be posted to Slack
    for ip in dangling_ips:
        slack_message["text"] += f"Account: {ip['Account']}, Domain: {ip['Domain']}, IP: {ip['IP']}\n"

    # Send the message to the Slack webhook URL
    response = requests.post(SLACK_WEBHOOK_URL, json=slack_message)

    if response.status_code == 200:
        print("Successfully sent message to Slack.")
    else:
        print(f"Failed to send message to Slack, status code: {response.status_code}")

def find_dangling_ips(region='ap-southeast-1'):
    """Compare DNS records against allocated Elastic IPs to find dangling IPs."""
    account_name = get_aws_account_name()  # Get AWS account name

    print("Fetching Route53 DNS records...")
    dns_records = get_route53_records()
    print(f"Fetched {len(dns_records)} DNS records.")

    print("Fetching allocated Elastic IPs...")
    allocated_ips = get_elastic_ips(region)
    print(f"Fetched {len(allocated_ips)} Elastic IPs.")

    dangling_ips = []

    for record in dns_records:
        if 'ResourceRecords' in record:
            for resource in record['ResourceRecords']:
                ip_address = resource['Value']
                # Check if the DNS record points to an IP address
                if ip_address.replace(".", "").isdigit():  # Simple IP address check
                    if ip_address not in allocated_ips and not is_private_ip(ip_address):
                        dangling_ips.append({
                            "Account": account_name,
                            "Domain": record['Name'],
                            "IP": ip_address
                        })

    # Output the results
    if dangling_ips:
        print("\nDangling IPs found (excluding private IPs):")
        for ip in dangling_ips:
            print(f"Account: {ip['Account']}, Domain: {ip['Domain']}, IP: {ip['IP']}")

        # Send the results to Slack
        send_to_slack(dangling_ips)
    else:
        print("\nNo dangling IPs found.")

if __name__ == "__main__":
    find_dangling_ips(region='ap-southeast-1')

