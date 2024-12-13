import boto3

def check_imdsv2(region):
    ec2_client = boto3.client('ec2', region_name=region)
    vulnerable_instances = []

    # Retrieve all instances in the region
    response = ec2_client.describe_instances()
    reservations = response.get('Reservations', [])

    for reservation in reservations:
        for instance in reservation.get('Instances', []):
            instance_id = instance['InstanceId']
            state = instance['State']['Name']
            metadata_options = instance.get('MetadataOptions', {})
            http_endpoint = metadata_options.get('HttpEndpoint', 'disabled')
            http_tokens = metadata_options.get('HttpTokens', 'optional')

            # Check if instance is not using IMDSv2
            if http_tokens != 'required':
                vulnerable_instances.append({
                    'InstanceId': instance_id,
                    'State': state,
                    'HttpEndpoint': http_endpoint,
                    'HttpTokens': http_tokens
                })

    return vulnerable_instances

if __name__ == "__main__":
    region = "ap-southeast-1"
    print(f"Checking EC2 IMDSv2 compliance in region: {region}")

    results = check_imdsv2(region)
    
    if results:
        print("\nVulnerable Instances (not using IMDSv2):")
        for instance in results:
            print(f"InstanceId: {instance['InstanceId']}, State: {instance['State']}, HttpEndpoint: {instance['HttpEndpoint']}, HttpTokens: {instance['HttpTokens']}")
    else:
        print("\nAll instances are secure and using IMDSv2.")

