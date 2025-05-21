import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta

def create_aws_session(use_profile, profile_name, access_key, secret_key, region):
    """Create AWS session based on provided credentials"""
    if use_profile:
        return boto3.Session(profile_name=profile_name, region_name=region)
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )

def get_iam_info(session):
    """Get IAM account information"""
    iam = session.client('iam')
    
    # Get account summary
    account_summary = iam.get_account_summary()
    
    # Get users
    users = iam.list_users().get('Users', [])
    
    # Get roles
    roles = iam.list_roles().get('Roles', [])
    
    # Get groups
    groups = iam.list_groups().get('Groups', [])
    
    # Get policies
    policies = iam.list_policies(Scope='Local').get('Policies', [])
    
    # Find users without MFA
    users_without_mfa = []
    for user in users:
        mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])
        if not mfa_devices.get('MFADevices'):
            users_without_mfa.append(user['UserName'])
    
    return {
        'account_summary': account_summary.get('SummaryMap', {}),
        'users': users,
        'roles': roles,
        'groups': groups,
        'policies': policies,
        'users_without_mfa': users_without_mfa
    }

def get_cloudtrail_events(session, days=7):
    """Get CloudTrail events for the specified number of days"""
    cloudtrail = session.client('cloudtrail')
    
    # Calculate date range
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    # Get events
    events = []
    response = cloudtrail.lookup_events(
        StartTime=start_date,
        EndTime=end_date
    )
    events.extend(response.get('Events', []))
    
    # Get additional pages if available
    while 'NextToken' in response and len(events) < 100:
        response = cloudtrail.lookup_events(
            NextToken=response['NextToken'],
            StartTime=start_date,
            EndTime=end_date
        )
        events.extend(response.get('Events', []))
    
    return events 