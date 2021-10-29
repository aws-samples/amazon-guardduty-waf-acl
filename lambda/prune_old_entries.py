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

logger = logging.getLogger()
logger.setLevel(logging.INFO)

#======================================================================================================================
# Variables
#======================================================================================================================

API_CALL_NUM_RETRIES = 1
ACLMETATABLE = os.environ['ACLMETATABLE']
RETENTION = os.environ['RETENTION']
CLOUDFRONT_IP_SET = os.environ['CLOUDFRONT_IP_SET']
REGIONAL_IP_SET = os.environ['REGIONAL_IP_SET']

CloudFrontIpSet = CLOUDFRONT_IP_SET.split("|")
RegionalIpSet = REGIONAL_IP_SET.split("|")

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
    logger.info("log --  hosts in ddb: %s" % (response))
    return response


def waf_update_ip_set(ip_set_name, ip_set_id, ip_set_scope, source_ips):
    logger.info('creating waf object')
    waf = boto3.client('wafv2')
    
    for attempt in range(API_CALL_NUM_RETRIES):
        logger.info('type of IPset: %s' % ip_set_id )
        try:
            response = waf.update_ip_set(
                Name = ip_set_name,
                Id = ip_set_id,
                Scope = ip_set_scope,
                LockToken = get_ip_set(ip_set_name, ip_set_id, ip_set_scope)['LockToken'],
                    Addresses=source_ips
                    )
            logger.info(response)
            logger.info("log -- waf_update_ip_set %s IPs %s - type %s successfully..." % (ip_set_id, source_ips, ip_set_scope))
        except Exception as e:
            logger.error(e)
            delay = math.pow(2, attempt)
            logger.info("log -- waf_update_ip_set retrying in %d seconds..." % (delay))
            time.sleep(delay)
        else:
            break
    else:
        logger.error("log -- waf_update_ip_set failed ALL attempts to call API")
        

def waf_update_ip_sets():
    ddb_ips = get_ddb_ips()
    if ddb_ips:
        logger.info('log -- adding Regional and CloudFront WAF ip entries')
        waf_update_ip_set(RegionalIpSet[0], RegionalIpSet[1], RegionalIpSet[2], ddb_ips)
        waf_update_ip_set(CloudFrontIpSet[0], CloudFrontIpSet[1], CloudFrontIpSet[2], ddb_ips)


def delete_netacl_rule(netacl_id, rule_no):

    ec2 = boto3.resource('ec2')
    network_acl = ec2.NetworkAcl(netacl_id)

    try:
        response = network_acl.delete_entry(
            Egress=False,
            RuleNumber=int(rule_no)
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            logger.info('log -- delete_netacl_rule successful')
            return True
        else:
            logger.error('log -- delete_netacl_rule FAILED')
            logger.info(response)
            return False
    except Exception as e:
        logger.error(e)


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
        logger.info('log -- delete_ddb_rule successful')
        return True
    else:
        logger.error('log -- delete_ddb_rule FAILED')
        logger.info(response['ResponseMetadata'])
        return False


#======================================================================================================================
# Lambda Entry Point
#======================================================================================================================


def lambda_handler(event, context):

    #logger.info("log -- Event: %s " % json.dumps(event))

    try:
        # timestamp is calculated in seconds
        expire_time = int(time.time()) - (int(RETENTION)*60)
        logger.info("log -- expire_time = %s" % expire_time)

        #scan the ddb table to find expired records
        ddb = boto3.resource('dynamodb')
        table = ddb.Table(ACLMETATABLE)
        response = table.scan(FilterExpression=Attr('CreatedAt').lt(expire_time) & Attr('Region').eq(os.environ['AWS_REGION']))

        if response['Items']:
            logger.info("log -- attempting to prune entries, %s." % (response)['Items'])

            # process each expired record
            for item in response['Items']:
                logger.info("deleting item: %s" %item)
                logger.info("HostIp %s" %item['HostIp'])
                HostIp = item['HostIp']
                try:
                    logger.info('log -- deleting netacl rule')
                    delete_netacl_rule(item['NetACLId'], item['RuleNo'])

                    # check if IP is also recorded in a fresh finding, don't remove IP from blocklist in that case
                    response_nonexpired = table.scan( FilterExpression=Attr('CreatedAt').gt(expire_time) & Attr('HostIp').eq(HostIp) )
                    logger.info('log -- deleting dynamodb item')
                    if len(response_nonexpired['Items']) == 0:
                        delete_ddb_rule(item['NetACLId'], item['CreatedAt'])
                        # no fresher entry found for that IP

                except Exception as e:
                    logger.error(e)
                    logger.error('log -- could not delete item')

            # Update WAF IP Sets
            logger.info('log -- update CloudFront Ip set %s and Regional IP set %s.' % (CLOUDFRONT_IP_SET, REGIONAL_IP_SET))
            waf_update_ip_sets()
            
            logger.info("Pruning Completed")
                
        else:
            logger.info("log -- no etntries older than %s hours... exiting GD2ACL pruning." % (int(RETENTION)/60))

    except Exception as e:
        logger.error('something went wrong')
        raise
