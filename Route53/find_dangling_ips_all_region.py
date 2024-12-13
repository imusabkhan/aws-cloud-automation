import boto3

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

def get_elastic_ips():
    """Fetch all allocated Elastic IPs across all regions."""
    session = boto3.Session()
    regions = session.get_available_regions('ec2')
    elastic_ips = set()

    for region in regions:
        ec2_client = session.client('ec2', region_name=region)
        try:
            response = ec2_client.describe_addresses()
            for address in response['Addresses']:
                elastic_ips.add(address['PublicIp'])
        except Exception as e:
            print(f"Error fetching EIPs in region {region}: {e}")

    return elastic_ips

def find_dangling_ips():
    """Compare DNS records against allocated Elastic IPs to find dangling IPs."""
    print("Fetching Route53 DNS records...")
    dns_records = get_route53_records()
    print(f"Fetched {len(dns_records)} DNS records.")

    print("Fetching allocated Elastic IPs...")
    allocated_ips = get_elastic_ips()
    print(f"Fetched {len(allocated_ips)} Elastic IPs.")

    dangling_ips = []

    for record in dns_records:
        if 'ResourceRecords' in record:
            for resource in record['ResourceRecords']:
                ip_address = resource['Value']
                # Check if the DNS record points to an IP address
                if ip_address.replace(".", "").isdigit():  # Simple IP address check
                    if ip_address not in allocated_ips:
                        dangling_ips.append({
                            "Name": record['Name'],
                            "IP": ip_address
                        })

    # Output the results
    if dangling_ips:
        print("\nDangling IPs found:")
        for ip in dangling_ips:
            print(f"Domain: {ip['Name']}, IP: {ip['IP']}")
    else:
        print("\nNo dangling IPs found.")

if __name__ == "__main__":
    find_dangling_ips()

