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
import logging
import os
import json
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
CLOUDFRONT_IP_SET = os.environ['CLOUDFRONT_IP_SET']
REGIONAL_IP_SET = os.environ['REGIONAL_IP_SET']

CloudFrontIpSet = CLOUDFRONT_IP_SET.split("|")
RegionalIpSet = REGIONAL_IP_SET.split("|")

logger.info("log -- regional ip set: %s -- cloudfront ip set: %s " % (RegionalIpSet, CloudFrontIpSet))


#======================================================================================================================
# Auxiliary Functions
#======================================================================================================================


def get_ip_set(ip_set_name, ip_set_id, ip_set_scope):
    client = boto3.client('wafv2')
    response = client.get_ip_set(
        Name = ip_set_name,
        Scope = ip_set_scope,
        Id = ip_set_id
        )
    return response


def get_ddb_ips():
    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACLMETATABLE)
    data = table.scan(FilterExpression=Attr('Region').eq(os.environ['AWS_REGION']))
    response = []
    for i in data['Items']:
        response.append(i['HostIp'] + "/32")
    logger.debug("log --  hosts in ddb: %s" % (response))
    return response


def find_values(id, json_repr):
    response = []

    def _decode_dict(a_dict):
        try:
            response.append(a_dict[id])
        except KeyError:
            pass
        return a_dict

    json.loads(json_repr, object_hook=_decode_dict) # Return value ignored.
    return response


# Update WAF IP set
def waf_update_ip_set(ip_set_name, ip_set_id, ip_set_scope, source_ips):
    logger.info('log -- creating waf object')
    waf = boto3.client('wafv2')

    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.update_ip_set(
            Name = ip_set_name,
            Id = ip_set_id,
            Scope = ip_set_scope,
            LockToken = get_ip_set(ip_set_name, ip_set_id, ip_set_scope)['LockToken'],
                Addresses=source_ips
            )
            logger.info("log -- waf_update_ip_set %s IP %s - type %s successfully..." % (ip_set_id, source_ips, ip_set_scope))
        except Exception as e:
            logger.error(e)
            delay = math.pow(2, attempt)
            logger.info("log -- waf_update_ip_set retrying in %d seconds..." % (delay))
            time.sleep(delay)
        else:
            break
    else:
        logger.error("log -- waf_update_ip_set failed ALL attempts to call WAF API")


def waf_update_ip_sets():
    ddb_ips = get_ddb_ips()
    if ddb_ips:
        logger.info('log -- adding Regional and CloudFront WAF ip entries')
        waf_update_ip_set(RegionalIpSet[0], RegionalIpSet[1], RegionalIpSet[2], ddb_ips)
        waf_update_ip_set(CloudFrontIpSet[0], CloudFrontIpSet[1], CloudFrontIpSet[2], ddb_ips)


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


#Update NACL and DDB state table
def update_nacl(netacl_id, host_ip, region):
    logger.info("log -- gd2acl entering update_nacl, netacl_id=%s, host_ip=%s" % (netacl_id, host_ip))

    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACLMETATABLE)

    hostipexists = table.query(
        KeyConditionExpression=Key('NetACLId').eq(netacl_id),
        FilterExpression=Attr('HostIp').eq(host_ip)
    )

    # Is HostIp already in table?
    if len(hostipexists['Items']) > 0:
        logger.info("log -- host IP %s already in table... exiting update." % (host_ip))
        return False

    else:

        # Get current NACL entries in DDB
        response = table.query(
            KeyConditionExpression=Key('NetACLId').eq(netacl_id)
        )

        # Get all the entries for NACL
        naclentries = response['Items']

        # Find oldest rule and available rule numbers from 71-80
        if naclentries:
            rulecount = response['Count']
            rulerange = list(range(71, 81))

            ddbrulerange = []
            naclrulerange = get_nacl_rules(netacl_id)

            for i in naclentries:
                ddbrulerange.append(int(i['RuleNo']))

            # Check state and exit if NACL rule not in sync with DDB
            ddbrulerange.sort()
            naclrulerange.sort()
            synccheck = set(naclrulerange).symmetric_difference(ddbrulerange)

            if ddbrulerange != naclrulerange:
                logger.info("log -- current DDB entries, %s." % (ddbrulerange))
                logger.info("log -- current NACL entries, %s." % (naclrulerange))
                logger.error('NACL rule state mismatch, %s exiting' % (sorted(synccheck)))
                exit()

            # Determine the NACL rule number and create rule
            if rulecount < 10:
                # Get the lowest rule number available in the range
                newruleno = min([x for x in rulerange if not x in naclrulerange])

                # Create new NACL rule, IP set entries and DDB state entry
                logger.info("log -- adding new rule %s, HostIP %s, to NACL %s." % (newruleno, host_ip, netacl_id))
                create_netacl_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno)
                create_ddb_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno, region=region)
                logger.info("log -- all possible NACL rule numbers, %s." % (rulerange))
                logger.info("log -- current DDB entries, %s." % (ddbrulerange))
                logger.info("log -- current NACL entries, %s." % (naclrulerange))
                logger.info("log -- new rule number, %s." % (newruleno))
                logger.info("log -- rule count for NACL %s is %s." % (netacl_id, int(rulecount) + 1))
                return True

            if rulecount >= 10:
                # Get oldest entry in DynamoDB table
                oldestrule = table.query(
                    KeyConditionExpression=Key('NetACLId').eq(netacl_id),
                    ScanIndexForward=True, # true = ascending, false = descending
                    Limit=1,
                )

                oldruleno = int((oldestrule)['Items'][0]['RuleNo'])
                oldrulets = int((oldestrule)['Items'][0]['CreatedAt'])
                oldhostip = oldestrule['Items'][0]['HostIp']
                newruleno = oldruleno

                # Delete old NACL rule and DDB state entry
                logger.info("log -- deleting current rule %s for IP %s from NACL %s." % (oldruleno, oldhostip, netacl_id))
                delete_netacl_rule(netacl_id=netacl_id, rule_no=oldruleno)
                delete_ddb_rule(netacl_id=netacl_id, created_at=oldrulets)

                # check if IP is also recorded in a fresh finding, don't remove IP from blacklist in that case
                response_nonexpired = table.scan( FilterExpression=Attr('CreatedAt').gt(oldrulets) & Attr('HostIp').eq(host_ip) )

                # Create new NACL rule, IP set entries and DDB state entry
                logger.info("log -- adding new rule %s, HostIP %s, to NACL %s." % (newruleno, host_ip, netacl_id))
                create_netacl_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno)
                create_ddb_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno, region=region)                
                logger.info("log -- all possible NACL rule numbers, %s." % (rulerange))
                logger.info("log -- current DDB entries, %s." % (ddbrulerange))
                logger.info("log -- current NACL entries, %s." % (naclrulerange))
                logger.info("log -- rule count for NACL %s is %s." % (netacl_id, int(rulecount)))
                return True

        else:
            # No entries in DDB Table start from 71
            naclrulerange = get_nacl_rules(netacl_id)
            newruleno = 71
            oldruleno = []
            rulecount = 0
            naclrulerange.sort()

            # Error and exit if NACL rules already present
            if naclrulerange:
                logger.error("log -- NACL %s, has existing entries, %s." % (netacl_id, naclrulerange))
                raise RuntimeError("NACL has existing entries.")

            # Create new NACL rule, IP set entries and DDB state entry
            logger.info("log -- adding new rule %s, HostIP %s, to NACL %s." % (newruleno, host_ip, netacl_id))
            create_netacl_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno)
            create_ddb_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno, region=region)
            logger.info("log -- rule count for NACL %s is %s." % (netacl_id, int(rulecount) + 1))
            return True

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
        logger.info("log -- successfully added new rule %s, HostIP %s, to NACL %s." % (rule_no, host_ip, netacl_id))
        return True
    else:
        logger.error("log -- error adding new rule %s, HostIP %s, to NACL %s." % (rule_no, host_ip, netacl_id))
        logger.info(response)
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
        logger.info("log -- successfully deleted rule %s, from NACL %s." % (rule_no, netacl_id))
        return True
    else:
        logger.info("log -- error deleting rule %s, from NACL %s." % (rule_no, netacl_id))
        logger.info(response)
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
        logger.info("log -- successfully added DDB state entry for rule %s, HostIP %s, NACL %s." % (rule_no, host_ip, netacl_id))
        return True
    else:
        logger.error("log -- error adding DDB state entry for rule %s, HostIP %s, NACL %s." % (rule_no, host_ip, netacl_id))
        logger.info(response)
        return False


# Delete DDB state entry for NACL rule
def delete_ddb_rule(netacl_id, created_at):

    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACLMETATABLE)

    response = table.delete_item(
        Key={
            'NetACLId': netacl_id,
            'CreatedAt': int(created_at)
            }
        )

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        logger.info("log -- successfully deleted DDB state entry for NACL %s." % (netacl_id))
        return True
    else:
        logger.error("log -- error deleting DDB state entry for NACL %s." % (netacl_id))
        logger.info(response)
        return False


# Send notification to SNS topic
def admin_notify(iphost, findingtype, naclid, region, instanceid, findingid):

    MESSAGE = ("GuardDuty to ACL Event Info:\r\n"
                 "Suspicious activity detected from host " + iphost + " due to " + findingtype +
                 "against EC2 Instance: " + instanceid + ". The following ACL resources were targeted for update as needed: " + '\n'
                 "CloudFront IP Set: " + CLOUDFRONT_IP_SET + '\n'
                 "Regional IP Set: " + REGIONAL_IP_SET + '\n'
                 "VPC NACL: " + naclid + '\n'
                 "Region: " + region + '\n'
                 "Finding Link: " + "https://console.aws.amazon.com/guardduty/home?region=" + region + "#/findings?macros=current&search=id%3D" + findingid
                )

    sns = boto3.client(service_name="sns")

    # Try to send the notification.
    try:

        sns.publish(
            TopicArn = SNSTOPIC,
            Message = MESSAGE,
            Subject='AWS GD2ACL Alert'
        )
        logger.info("log -- send notification sent to SNS Topic: %s" % (SNSTOPIC))

    # Display an error if something goes wrong.
    except ClientError as e:
        logger.error('log -- error sending notification.')
        raise


#======================================================================================================================
# Lambda Entry Point
#======================================================================================================================


# Lambda handler
def lambda_handler(event, context):

    logger.info("log -- Event: %s " % json.dumps(event))

    try:
        if 'Recon:EC2/PortProbe' in event["detail"]["type"]:
            HostIp = []
            FindingID = event["detail"]["id"]
            remoteIpDetail = find_values('remoteIpDetails', json.dumps(event))
            Region = event["region"]
            SubnetId = event["detail"]["resource"]["instanceDetails"]["networkInterfaces"][0]["subnetId"]
            for i in event["detail"]["service"]["action"]["portProbeAction"]["portProbeDetails"]:
                HostIp.append(str(i["remoteIpDetails"]["ipAddressV4"]))
            instanceID = event["detail"]["resource"]["instanceDetails"]["instanceId"]
            NetworkAclId = get_netacl_id(subnet_id=SubnetId)
        else:
            HostIp = []
            FindingID = event["detail"]["id"]
            Region = event["region"]
            instanceID = find_values('instanceId', json.dumps(event))
            SubnetId = find_values('subnetId', json.dumps(event))
            remoteIpDetail = find_values('remoteIpDetails', json.dumps(event))
            if not remoteIpDetail or not SubnetId:
                pass
            else:
                HostIp.append((remoteIpDetail)[0]["ipAddressV4"])
                NetworkAclId = get_netacl_id(subnet_id=SubnetId[0])


        if len(HostIp) > 0 and NetworkAclId:
            logger.info("log -- gd2acl attempting to process finding data: instanceID: %s - SubnetId: %s - RemoteHostIp: %s" % (instanceID[0], SubnetId[0], HostIp))
            update_counter = 0

            # Update VPC NACL
            for ip in HostIp:
                response = update_nacl(netacl_id=NetworkAclId, host_ip=ip, region=Region)
                if response is True:
                    update_counter = update_counter + 1

            # Update WAF IP Sets
            if update_counter > 0:
                logger.info('log -- adding Regional and CloudFront WAF IP set entry for host, %s from CloudFront Ip set %s and REGION IP set %s.' % (HostIp, CLOUDFRONT_IP_SET, REGIONAL_IP_SET))
                waf_update_ip_sets()

            #Send Notification
            admin_notify(str(HostIp), event["detail"]["type"], NetworkAclId, Region, str(instanceID), str(FindingID))

            logger.info("log -- processing GuardDuty finding completed successfully")

        else:
            logger.warning("log -- unable to determine required info from finding - instanceID: %s, SubnetId: %s, RemoteIp: %s" % (instanceID, SubnetId, HostIp))
            pass

    except Exception as e:
        logger.error('log -- something went wrong.')
        raise
