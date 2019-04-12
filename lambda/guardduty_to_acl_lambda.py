# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# MIT No Attribution
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import boto3
import math
import time
import json
import datetime
import logging
import os
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


#======================================================================================================================
# Variables
#======================================================================================================================

API_CALL_NUM_RETRIES = 1
ACLMETATABLE = os.environ['ACLMETATABLE']
SNSTOPIC = os.environ['SNSTOPIC']
CLOUDFRONT_IP_SET_ID = os.environ['CLOUDFRONT_IP_SET_ID']
ALB_IP_SET_ID = os.environ['ALB_IP_SET_ID']

#======================================================================================================================
# Auxiliary Functions
#======================================================================================================================


# Update WAF IP set
def waf_update_ip_set(waf_type, ip_set_id, source_ip):

    if waf_type == 'alb':
        session = boto3.session.Session(region_name=os.environ['AWS_REGION'])
        waf = session.client('waf-regional')
    elif waf_type == 'cloudfront':
        waf = boto3.client('waf')

    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.update_ip_set(IPSetId=ip_set_id,
                ChangeToken=waf.get_change_token()['ChangeToken'],
                Updates=[{
                    'Action': 'INSERT',
                    'IPSetDescriptor': {
                        'Type': 'IPV4',
                        'Value': "%s/32"%source_ip
                    }
                }]
            )
            logger.info("[waf_update_ip_set] added IP %s to IPset %s, WAF type %s successfully..." % (source_ip, ip_set_id, waf_type))
        except Exception as e:
            logger.error(e)
            delay = math.pow(2, attempt)
            logger.info("[waf_update_ip_set] Retrying in %d seconds..." % (delay))
            time.sleep(delay)
        else:
            break
    else:
        logger.info("[waf_update_ip_set] Failed ALL attempts to call API")


# Get the current NACL Id associated with subnet
def get_netacl_id(subnet_id):

    try:
        ec2 = boto3.client('ec2')
        response = ec2.describe_network_acls(
            Filters=[
                {
                    'Name': 'association.subnet-id',
                    'Values': [
                        subnet_id,
                    ]
                }
            ]
        )


        netacls = response['NetworkAcls'][0]['Associations']

        for i in netacls:
            if i['SubnetId'] == subnet_id:
                netaclid = i['NetworkAclId']

        return netaclid
    except Exception as e:
        return []


# Get the current NACL rules in the range 71-80
def get_nacl_rules(netacl_id):
    ec2 = boto3.client('ec2')
    response = ec2.describe_network_acls(
        NetworkAclIds=[
            netacl_id,
            ]
    )

    naclrules = []

    for i in response['NetworkAcls'][0]['Entries']:
        naclrules.append(i['RuleNumber'])
        
    naclrulesf = list(filter(lambda x: 71 <= x <= 80, naclrules))

    return naclrulesf


# Get current DDB state data for NACL Id
def get_nacl_meta(netacl_id):
    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACLMETATABLE)
    ec2 = boto3.client('ec2')
    response = ec2.describe_network_acls(
        NetworkAclIds=[
            netacl_id,
            ]
    )

    # Get entries in DynamoDB table
    ddbresponse = table.scan()
    ddbentries = response['Items']

    netacl = ddbresponse['NetworkAcls'][0]['Entries']
    naclentries = []

    for i in netacl:
            entries.append(i)

    return naclentries


#Update NACL and DDB state table
def update_nacl(netacl_id, host_ip, region):
    logger.info("entering update_nacl, netacl_id=%s, host_ip=%s" % (netacl_id, host_ip))

    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACLMETATABLE)
    timestamp = int(time.time())

    hostipexists = table.query(
        KeyConditionExpression=Key('NetACLId').eq(netacl_id),
        FilterExpression=Attr('HostIp').eq(host_ip)
    )

    # Get oldest entry in DynamoDB table
    oldestrule = table.query(
        KeyConditionExpression=Key('NetACLId').eq(netacl_id),
        ScanIndexForward=True, # true = ascending, false = descending
        Limit=1,
    )

    # Is HostIp already in table?
    if len(hostipexists['Items']) > 0:
        logger.info("log -- host IP %s already in table... exiting NACL update." % (host_ip))

    else:

        # Get current NACL entries in DDB
        response = table.query(
            KeyConditionExpression=Key('NetACLId').eq(netacl_id)
        )

        # Get all the entries for NACL
        naclentries = response['Items']

        # Find oldest rule and available rule numbers from 71-80
        if naclentries:
            oldruleno = int((oldestrule)['Items'][0]['RuleNo'])
            oldrulets = int((oldestrule)['Items'][0]['CreatedAt'])
            rulecount = response['Count']
            rulerange = list(range(71, 81))

            ddbrulerange = []
            naclrulerange = get_nacl_rules(netacl_id)

            for i in naclentries:
                ddbrulerange.append(int(i['RuleNo']))

            ddbrulerange.sort()
            naclrulerange.sort()

            synccheck = set(naclrulerange).symmetric_difference(ddbrulerange)

            # Error and exit if NACL rule state not in sync
            if ddbrulerange != naclrulerange:
                logger.info("log -- current DDB entries, %s." % (ddbrulerange))
                logger.info("log -- current NACL entries, %s." % (naclrulerange))
                logger.error('NACL rule state mismatch, %s exiting' % (sorted(synccheck)))
                exit()

            # Set the rule number
            if rulecount < 10:
                # Get the lowest rule number available in the range
                newruleno = min([x for x in rulerange if not x in naclrulerange])

                # Create NACL rule and DDB state entry
                create_netacl_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno)
                create_ddb_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno, region=region)
                
                logger.info("log -- all possible NACL rule numbers, %s" % (rulerange))
                logger.info("log -- current DDB entries, %s." % (ddbrulerange))
                logger.info("log -- current NACL entries, %s." % (naclrulerange))
                logger.info("log -- new rule number, %s." % (newruleno))
                logger.info("log -- add new rule %s, HostIP %s, to NACL %s." % (newruleno, host_ip, netacl_id))
                logger.info("log -- rule count for NACL %s is %s." % (netacl_id, int(rulecount) + 1))

            else:
                newruleno = oldruleno

                # Delete old NACL rule and DDB state entry
                delete_netacl_rule(netacl_id=netacl_id, rule_no=oldruleno)
                delete_ddb_rule(netacl_id=netacl_id, created_at=oldrulets)

                logger.info("log -- delete rule %s, from NACL %s." % (oldruleno, netacl_id))

                # Create NACL rule and DDB state entry
                create_netacl_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno)
                create_ddb_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno, region=region)

                logger.info("log -- all possible NACL rule numbers, %s" % (rulerange))
                logger.info("log -- current DDB entries, %s." % (ddbrulerange))
                logger.info("log -- current NACL entries, %s." % (naclrulerange))
                logger.info("log -- new rule number, %s." % (newruleno))
                logger.info("log -- add new rule %s, HostIP %s, to NACL %s." % (newruleno, host_ip, netacl_id))
                logger.info("log -- rule count for NACL %s is %s." % (netacl_id, int(rulecount)))

        else:
            # No entries in DDB Table start from 71
            naclrulerange = get_nacl_rules(netacl_id)
            newruleno = 71
            oldruleno = []
            rulecount = 0
            naclrulerange.sort()

            # Error and exit if NACL rules already present
            if naclrulerange:
                logger.error("log -- NACL has existing entries, %s." % (naclrulerange))
                exit()

            # Create NACL rule and DDB state entry
            create_netacl_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno)
            create_ddb_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno, region=region)

            logger.info("log -- add new rule %s, HostIP %s, to NACL %s." % (newruleno, host_ip, netacl_id))
            logger.info("log -- rule count for NACL %s is %s." % (netacl_id, int(rulecount) + 1))

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return True
        else:
            return False


# Create NACL rule
def create_netacl_rule(netacl_id, host_ip, rule_no):

    ec2 = boto3.resource('ec2')
    network_acl = ec2.NetworkAcl(netacl_id)

    response = network_acl.create_entry(
    CidrBlock = host_ip + '/32',
    Egress=False,
    PortRange={
        'From': 0,
        'To': 65535
    },
    Protocol='-1',
    RuleAction='deny',
    RuleNumber= rule_no
    )

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False


# Delete NACL rule
def delete_netacl_rule(netacl_id, rule_no):

    ec2 = boto3.resource('ec2')
    network_acl = ec2.NetworkAcl(netacl_id)

    response = network_acl.delete_entry(
        Egress=False,
        RuleNumber=rule_no
    )

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False


# Create DDB state entry for NACL rule
def create_ddb_rule(netacl_id, host_ip, rule_no, region):

    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACLMETATABLE)
    timestamp = int(time.time())

    response = table.put_item(
        Item={
            'NetACLId': netacl_id,
            'CreatedAt': timestamp,
            'HostIp': str(host_ip),
            'RuleNo': str(rule_no),
            'Region': str(region)
            }
        )

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False


# Delete DDB state entry for NACL rule
def delete_ddb_rule(netacl_id, created_at):

    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACLMETATABLE)
    timestamp = int(time.time())

    response = table.delete_item(
        Key={
            'NetACLId': netacl_id,
            'CreatedAt': int(created_at)
            }
        )

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False


# Send notification to SNS topic
def admin_notify(iphost, findingtype, naclid, region, instanceid):

    MESSAGE = ("GuardDuty to ACL Event Info:\r\n"
                 "Suspicious activity detected from host " + iphost + " due to " + findingtype + "."
                 "  The following ACL resources were targeted for update as needed; "
                 "CloudFront IP Set: " + CLOUDFRONT_IP_SET_ID + ", "
                 "Regional IP Set: " + ALB_IP_SET_ID + ", "
                 "VPC NACL: " + naclid + ", "
                 "EC2 Instance: " + instanceid + ", "
                 "Region: " + region + ". "
                )

    sns = boto3.client(service_name="sns")

    # Try to send the notification.
    try:

        sns.publish(
            TopicArn = SNSTOPIC,
            Message = MESSAGE,
            Subject='AWS GD2ACL Alert'
        )
        logger.info("Notification sent to SNS Topic: %s" % (SNSTOPIC))

    # Display an error if something goes wrong.
    except ClientError as e:
        logger.error('Error sending notification.')
        raise


#======================================================================================================================
# Lambda Entry Point
#======================================================================================================================


# Main Lambda handler
def lambda_handler(event, context):

    logger.info("log -- Event: %s " % json.dumps(event))

    try:

        if event["detail"]["type"] == 'Recon:EC2/PortProbeUnprotectedPort':
            Region = event["region"]
            SubnetId = event["detail"]["resource"]["instanceDetails"]["networkInterfaces"][0]["subnetId"]
            HostIp = event["detail"]["service"]["action"]["portProbeAction"]["portProbeDetails"][0]["remoteIpDetails"]["ipAddressV4"]
            instanceID = event["detail"]["resource"]["instanceDetails"]["instanceId"]
            NetworkAclId = get_netacl_id(subnet_id=SubnetId)

        else:
            Region = event["region"]
            SubnetId = event["detail"]["resource"]["instanceDetails"]["networkInterfaces"][0]["subnetId"]
            HostIp = event["detail"]["service"]["action"]["networkConnectionAction"]["remoteIpDetails"]["ipAddressV4"]
            instanceID = event["detail"]["resource"]["instanceDetails"]["instanceId"]
            NetworkAclId = get_netacl_id(subnet_id=SubnetId)

        if NetworkAclId:
            # Update global and regional IP Sets
            waf_update_ip_set('alb', os.environ['ALB_IP_SET_ID'], HostIp)
            waf_update_ip_set('cloudfront', os.environ['CLOUDFRONT_IP_SET_ID'], HostIp)

            # Update VPC NACL
            response = update_nacl(netacl_id=NetworkAclId,host_ip=HostIp, region=Region)

            #Send Notification
            admin_notify(HostIp, event["detail"]["type"], NetworkAclId, Region, instanceid = instanceID)

            logger.info("processing GuardDuty finding completed successfully")

        else:
            logger.info("Unable to determine NetworkAclId for instanceID: %s, HostIp: %s, SubnetId: %s. Confirm resources exist." % (instanceID, HostIp, SubnetId))
            pass

    except Exception as e:
        logger.error('Something went wrong.')
        raise
