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
import sys
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

#======================================================================================================================
# Variables
#======================================================================================================================

ACLMETATABLE = "GuardDutytoACL-GuardDutytoACLDDBTable-ID"
AWS_REGION = "us-east-1"

#======================================================================================================================
# Auxiliary Functions
#======================================================================================================================

# used to color text
class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

# validate command line
if len(sys.argv) != 2:
	print('Usage: gd2acl-sync-check.py <target NACL Id>');
	exit(1);

# set target vpc nacl
targnacl = sys.argv[1];

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


def check_nacl(netacl_id, region):
    logger.info("checking nacl, netacl_id=%s." % (netacl_id))

    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACLMETATABLE)

    # Get current NACL entries in DDB
    response = table.query(
        KeyConditionExpression=Key('NetACLId').eq(netacl_id)
    )

    # Get all the entries for NACL
    naclentries = response['Items']

    # Get the range and check the state
    if naclentries:
        rulecount = response['Count']
        rulerange = list(range(71, 81))

        ddbrulerange = []
        naclrulerange = get_nacl_rules(netacl_id)

        for i in naclentries:
            ddbrulerange.append(int(i['RuleNo']))
        
        ddbrulerange.sort()
        naclrulerange.sort()

        synccheck = set(naclrulerange).symmetric_difference(ddbrulerange)

        if ddbrulerange != naclrulerange:
            logger.info("log -- current DDB entries, %s." % (ddbrulerange))
            logger.info("log -- current NACL entries, %s." % (naclrulerange))
            logger.info("log -- rule count, %s." % (rulecount))
            print(bcolors.FAIL + 'Rule state mismatch for NACL, %s' % (sorted(synccheck)) + bcolors.ENDC)
        else:
            logger.info("log -- current DDB entries, %s." % (ddbrulerange))
            logger.info("log -- current NACL entries, %s." % (naclrulerange))
            logger.info("log -- rule count for NACL %s is %s." % (netacl_id, rulecount))
            print(bcolors.OKGREEN + 'Rule state is OK for NACL, %s.' % (netacl_id) + bcolors.ENDC)

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return True
        else:
            return False

#======================================================================================================================
# Run main function
#======================================================================================================================

try:
    check_nacl(targnacl, AWS_REGION)

except Exception as e:
    logger.error('Something went wrong.')
    raise