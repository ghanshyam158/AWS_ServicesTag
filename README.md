# AWS_ServicesTag
What the Script Does
The script is an AWS Lambda function that collects information about various AWS resources in your account. It uses the AWS SDK for Python (Boto3) to interact with different AWS services and gathers details on the following:
1.	EC2 Instances: Lists running and stopped EC2 instances, including their IDs, states, and tags.
2.	S3 Buckets: Retrieves all S3 buckets, their locations, and associated tags.
3.	Lambda Functions: Lists all Lambda functions and their tags.
4.	DynamoDB Tables: Lists DynamoDB tables and their tags.
5.	ECR Repositories: Lists Amazon Elastic Container Registry (ECR) repositories and their tags.
6.	ECS Clusters and Services: Lists ECS clusters and their services, including their tags.
7.	SNS Topics: Lists SNS topics and their tags.
8.	Secrets Manager Secrets: Retrieves secrets from AWS Secrets Manager and their tags.
9.	SQS Queues: Lists SQS queues and their tags.
10.	KMS Keys: Retrieves AWS Key Management Service (KMS) keys and their tags.
11.	CodeCommit Repositories: Lists CodeCommit repositories and their tags.
12.	Load Balancers: Lists Application and Network Load Balancers, including their tags.
13.	VPCs: Lists VPCs (Virtual Private Clouds) and their tags.
14.	CloudTrail Trails: Lists CloudTrail trails and their tags.
The script gathers this information and formats it into a JSON object, which is then returned as the Lambda function's output.
Regional Considerations
The script does interact with services that can be regional, such as:
•	S3 Buckets: Buckets can be located in different regions, and the script attempts to handle this by querying each bucket's location.
•	DynamoDB Tables: The script assumes that DynamoDB tables are in the same region as the Lambda function. If you have tables in other regions, you'll need to modify the script to handle multiple regions.
•	ECR Repositories, Lambda Functions, and Other Services: These are generally queried from the region in which the Lambda function is running.
Running in Any Region
By default, the Lambda function operates in the region where it is deployed. However, to run this script in any region, you'll need to:
Modify Region for Each Client: Adjust the Boto3 clients to specify the desired region. For example:
ec2_client = boto3.client('ec2', region_name='us-west-2')

Handle Multiple Regions: If you want the script to handle resources across multiple regions, you'll need to loop through a list of regions, creating Boto3 clients for each region and aggregating the results.

Here’s an example snippet to modify the script to handle multiple regions:
regions = ['us-east-1', 'us-west-2', 'eu-west-1']  # Example list of regions

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

for region in regions:
    ec2_client = boto3.client('ec2', region_name=region)
    s3_client = boto3.client('s3', region_name=region)
    lambda_client = boto3.client('lambda', region_name=region)
    dynamodb_client = boto3.client('dynamodb', region_name=region)
    ecr_client = boto3.client('ecr', region_name=region)
    ecs_client = boto3.client('ecs', region_name=region)
    sns_client = boto3.client('sns', region_name=region)
    secretsmanager_client = boto3.client('secretsmanager', region_name=region)
    sqs_client = boto3.client('sqs', region_name=region)
    kms_client = boto3.client('kms', region_name=region)
    codecommit_client = boto3.client('codecommit', region_name=region)
    elb_client = boto3.client('elbv2', region_name=region)
    cloudtrail_client = boto3.client('cloudtrail', region_name=region)
    
    # ... rest of the script to gather data for each region


