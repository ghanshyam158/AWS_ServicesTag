import boto3
import json
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    ec2_client = boto3.client('ec2')
    s3_client = boto3.client('s3')
    lambda_client = boto3.client('lambda')
    dynamodb_client = boto3.client('dynamodb')
    ecr_client = boto3.client('ecr')
    ecs_client = boto3.client('ecs')
    sns_client = boto3.client('sns')
    secretsmanager_client = boto3.client('secretsmanager')
    sqs_client = boto3.client('sqs')
    kms_client = boto3.client('kms')
    codecommit_client = boto3.client('codecommit')
    elb_client = boto3.client('elbv2')  # For Application and Network Load Balancers
    cloudtrail_client = boto3.client('cloudtrail')  # For CloudTrail

    results = {
        'RunningInstances': [],
        'StoppedInstances': [],
        'S3Buckets': [],
        'LambdaFunctions': [],
        'DynamoDBTables': [],
        'ECRRepositories': [],
        'ECSClusters': [],
        'ECSServices': [],
        'SNSTopics': [],
        'Secrets': [],
        'SQSQueues': [],
        'KMSKeys': [],
        'CodeCommitRepositories': [],
        'LoadBalancers': [],
        'VPCs': [],
        'CloudTrailTrails': []
    }

    # Retrieve all EC2 instances
    reservations = ec2_client.describe_instances()
    for reservation in reservations['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            state = instance['State']['Name']
            tags = instance.get('Tags', [])
            instance_info = {
                'InstanceId': instance_id,
                'State': state,
                'Tags': tags if tags else 'No tags'
            }
            
            if state == 'running':
                results['RunningInstances'].append(instance_info)
            elif state == 'stopped':
                results['StoppedInstances'].append(instance_info)

    # Retrieve all S3 buckets
    buckets = s3_client.list_buckets()
    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']
        try:
            location = s3_client.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
            regional_s3_client = boto3.client('s3', region_name=location if location else 'us-east-1')
            tags = regional_s3_client.get_bucket_tagging(Bucket=bucket_name).get('TagSet', [])
            results['S3Buckets'].append({
                'BucketName': bucket_name,
                'Tags': tags if tags else 'No tags'
            })
        except s3_client.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchTagSet':
                results['S3Buckets'].append({
                    'BucketName': bucket_name,
                    'Tags': 'No tags'
                })
            else:
                raise

    # Retrieve all Lambda functions
    lambda_functions = lambda_client.list_functions()
    for function in lambda_functions['Functions']:
        function_name = function['FunctionName']
        try:
            tags = lambda_client.list_tags(Resource=function['FunctionArn'])
            results['LambdaFunctions'].append({
                'FunctionName': function_name,
                'Tags': tags.get('Tags', 'No tags')
            })
        except lambda_client.exceptions.ResourceNotFoundException:
            results['LambdaFunctions'].append({
                'FunctionName': function_name,
                'Tags': 'No tags'
            })

    # Retrieve all DynamoDB tables
    tables = dynamodb_client.list_tables()
    for table_name in tables['TableNames']:
        try:
            tags = dynamodb_client.list_tags_of_resource(ResourceArn=f'arn:aws:dynamodb:{context.invoked_function_arn.split(":")[3]}:{context.invoked_function_arn.split(":")[4]}:table/{table_name}')
            results['DynamoDBTables'].append({
                'TableName': table_name,
                'Tags': tags.get('Tags', 'No tags')
            })
        except dynamodb_client.exceptions.ResourceNotFoundException:
            results['DynamoDBTables'].append({
                'TableName': table_name,
                'Tags': 'No tags'
            })

    # Retrieve all ECR repositories
    ecr_repositories = ecr_client.describe_repositories()
    for repository in ecr_repositories['repositories']:
        repository_name = repository['repositoryName']
        try:
            tags = ecr_client.list_tags_for_resource(resourceArn=f'arn:aws:ecr:{context.invoked_function_arn.split(":")[3]}:{context.invoked_function_arn.split(":")[4]}:repository/{repository_name}')
            results['ECRRepositories'].append({
                'RepositoryName': repository_name,
                'Tags': tags.get('tags', 'No tags')
            })
        except ecr_client.exceptions.RepositoryNotFoundException:
            results['ECRRepositories'].append({
                'RepositoryName': repository_name,
                'Tags': 'No tags'
            })

    # Retrieve all ECS clusters
    clusters = ecs_client.list_clusters()
    for cluster_arn in clusters['clusterArns']:
        try:
            tags = ecs_client.list_tags_for_resource(resourceArn=cluster_arn)
            results['ECSClusters'].append({
                'ClusterArn': cluster_arn,
                'Tags': tags.get('tags', 'No tags')
            })
        except ecs_client.exceptions.ClientException:
            results['ECSClusters'].append({
                'ClusterArn': cluster_arn,
                'Tags': 'No tags'
            })

    # Retrieve all ECS services
    for cluster_arn in clusters['clusterArns']:
        services = ecs_client.list_services(cluster=cluster_arn)
        for service_arn in services['serviceArns']:
            try:
                tags = ecs_client.list_tags_for_resource(resourceArn=service_arn)
                results['ECSServices'].append({
                    'ServiceArn': service_arn,
                    'Tags': tags.get('tags', 'No tags')
                })
            except ecs_client.exceptions.ClientException:
                results['ECSServices'].append({
                    'ServiceArn': service_arn,
                    'Tags': 'No tags'
                })

    # Retrieve all SNS topics
    sns_topics = sns_client.list_topics()
    for topic_arn in sns_topics['Topics']:
        topic_arn = topic_arn['TopicArn']
        try:
            tags = sns_client.list_tags_for_resource(ResourceArn=topic_arn)
            results['SNSTopics'].append({
                'TopicArn': topic_arn,
                'Tags': tags.get('Tags', 'No tags')
            })
        except sns_client.exceptions.NotFoundException:
            results['SNSTopics'].append({
                'TopicArn': topic_arn,
                'Tags': 'No tags'
            })

    # Retrieve all Secrets Manager secrets
    secrets = secretsmanager_client.list_secrets()
    for secret in secrets['SecretList']:
        secret_arn = secret['ARN']
        try:
            secret_details = secretsmanager_client.describe_secret(SecretId=secret_arn)
            tags = secret_details.get('Tags', 'No tags')
            results['Secrets'].append({
                'SecretArn': secret_arn,
                'Tags': tags if tags else 'No tags'
            })
        except secretsmanager_client.exceptions.ResourceNotFoundException:
            results['Secrets'].append({
                'SecretArn': secret_arn,
                'Tags': 'No tags'
            })
            
    # Retrieve all SQS queues
    queues = sqs_client.list_queues()
    
    if 'QueueUrls' in queues:
        for queue_url in queues['QueueUrls']:
            try:
                tags = sqs_client.list_queue_tags(QueueUrl=queue_url)
                results['SQSQueues'].append({
                    'QueueUrl': queue_url,
                    'Tags': tags.get('Tags', 'No tags')
                })
            except sqs_client.exceptions.QueueDoesNotExist:
                results['SQSQueues'].append({
                    'QueueUrl': queue_url,
                    'Tags': 'No tags'
                })

    # Retrieve all KMS keys
    try:
        kms_keys = kms_client.list_keys()
        for key in kms_keys['Keys']:
            key_id = key['KeyId']
            try:
                tags = kms_client.list_resource_tags(KeyId=key_id)
                results['KMSKeys'].append({
                    'KeyId': key_id,
                    'Tags': tags.get('Tags', 'No tags')
                })
            except kms_client.exceptions.NotFoundException:
                results['KMSKeys'].append({
                    'KeyId': key_id,
                    'Tags': 'No tags'
                })
    except kms_client.exceptions.ClientError as e:
        results['KMSKeys'].append({
            'KeyId': 'N/A',
            'Tags': f'Error retrieving keys: {str(e)}'
        })

    try:
        # Retrieve all CodeCommit repositories
        repos = codecommit_client.list_repositories()
        account_id = context.invoked_function_arn.split(":")[4]  # Extract account ID from Lambda context
        region = context.invoked_function_arn.split(":")[3]      # Extract region from Lambda context
        
        for repo in repos['repositories']:
            repo_name = repo['repositoryName']
            repo_arn = f'arn:aws:codecommit:{region}:{account_id}:repository/{repo_name}'
            
            try:
                # Attempt to get tags for the repository
                tags_response = codecommit_client.list_tags_for_resource(resourceArn=repo_arn)
                tags = tags_response.get('tags', {})
            except codecommit_client.exceptions.InvalidRepositoryNameException:
                print(f'Invalid repository name detected: {repo_name}')
                tags = {}
            except codecommit_client.exceptions.ClientError as e:
                print(f'Error retrieving tags for {repo_name}: {e}')
                tags = {}
            
            # Convert tags dictionary to a JSON string for better readability
            tags_json = json.dumps(tags) if tags else "No tags found"
            
            results['CodeCommitRepositories'].append({
                'RepositoryArn': repo_arn,
                'Tags': tags_json
            })

    except codecommit_client.exceptions.ClientError as e:
        results['CodeCommitRepositories'].append({
            'RepositoryArn': 'N/A',
            'Tags': f'Error retrieving repositories: {str(e)}'
        })

    # Retrieve all ELBs
    try:
        load_balancers = elb_client.describe_load_balancers()
        for lb in load_balancers['LoadBalancers']:
            lb_arn = lb['LoadBalancerArn']
            try:
                tags_response = elb_client.describe_tags(ResourceArns=[lb_arn])
                tags = tags_response.get('TagDescriptions', [{}])[0].get('Tags', 'No tags')
                results['LoadBalancers'].append({
                    'LoadBalancerArn': lb_arn,
                    'Tags': tags if tags else 'No tags'
                })
            except ClientError as e:
                print(f"Error retrieving tags for Load Balancer {lb_arn}: {e}")
                results['LoadBalancers'].append({
                    'LoadBalancerArn': lb_arn,
                    'Tags': 'No tags'
                })
    except ClientError as e:
        print(f"Error retrieving Load Balancers: {e}")

    # Retrieve all VPCs
    try:
        vpcs = ec2_client.describe_vpcs()
        for vpc in vpcs['Vpcs']:
            vpc_id = vpc['VpcId']
            try:
                tags_response = ec2_client.describe_tags(Filters=[
                    {'Name': 'resource-id', 'Values': [vpc_id]}
                ])
                tags = tags_response.get('Tags', 'No tags')
                results['VPCs'].append({
                    'VpcId': vpc_id,
                    'Tags': tags if tags else 'No tags'
                })
            except ClientError as e:
                print(f"Error retrieving tags for VPC {vpc_id}: {e}")
                results['VPCs'].append({
                    'VpcId': vpc_id,
                    'Tags': 'No tags'
                })
    except ClientError as e:
        print(f"Error retrieving VPCs: {e}")

    # Retrieve all CloudTrail trails
    try:
        trails_response = cloudtrail_client.list_trails()
        print(f"Tags Response: {tags_response}")

        trails = trails_response.get('trailList', [])

        if trails:
            for trail in trails:
                trail_arn = trail['TrailARN']
                try:
                    tags_response = cloudtrail_client.list_tags_for_resource(ResourceIdList=[trail_arn])
                    tags = tags_response.get('TagsList', [])
                    results['CloudTrailTrails'].append({
                        'TrailArn': trail_arn,
                        'Tags': tags if tags else 'No tags'
                    })
                except ClientError as e:
                    print(f"Error retrieving tags for CloudTrail trail {trail_arn}: {e}")
                    results['CloudTrailTrails'].append({
                        'TrailArn': trail_arn,
                        'Tags': f'Error retrieving tags: {str(e)}'
                    })
        else:
            results['CloudTrailTrails'].append({
                'TrailArn': 'N/A',
                'Tags': 'No CloudTrail trails found'
            })
    except ClientError as e:
        print(f"Error retrieving CloudTrail trails: {e}")
        results['CloudTrailTrails'].append({
            'TrailArn': 'N/A',
            'Tags': f'Error retrieving trails: {str(e)}'
        })

    return {
        'statusCode': 200,
        'body': json.dumps(results, indent=4)
    }
