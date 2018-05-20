    
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
# Constants
#======================================================================================================================
API_CALL_NUM_RETRIES = 1
ACLMETATABLE = os.environ['ACLMETATABLE']

#======================================================================================================================
# Auxiliary Functions
#======================================================================================================================
def waf_update_ip_set(waf_type, ip_set_id, source_ip):

    if waf_type == 'alb':
        logger.info('creating waf regional object')
        session = boto3.session.Session(region_name=os.environ['AWS_REGION'])
        waf = session.client('waf-regional')
    elif waf_type == 'cloudfront':
        logger.info('creating waf global object')
        waf = boto3.client('waf')
    logger.info('type of WAF: %s' % waf_type )
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.update_ip_set(IPSetId=ip_set_id,
                ChangeToken=waf.get_change_token()['ChangeToken'],
                Updates=[{
                    'Action': 'DELETE',
                    'IPSetDescriptor': {
                        'Type': 'IPV4',
                        'Value': "%s/32"%source_ip
                    }
                }]
            )
            logger.info(response)
            logger.info('successfully deleted ip %s' %source_ip)
        except Exception as e:
            logger.error(e)
            delay = math.pow(2, attempt)
            logger.info("[waf_update_ip_set] Retrying in %d seconds..." % (delay))
            time.sleep(delay)
        else:
            break
    else:
        logger.error("[waf_update_ip_set] Failed ALL attempts to call API")




def delete_netacl_rule(netacl_id, rule_no):

    ec2 = boto3.resource('ec2')
    network_acl = ec2.NetworkAcl(netacl_id)

    try:
        response = network_acl.delete_entry(
            Egress=False,
            RuleNumber=int(rule_no)
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            logger.info('delete_netacl_rule successful')
            return True
        else:
            logger.info('delete_netacl_rule FAILED')
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
        logger.info('delete_ddb_rule successful')
        return True
    else:
        logger.error('delete_ddb_rule FAILED')
        logger.info(response['ResponseMetadata'])
        return False


#======================================================================================================================
# Lambda Entry Point
#======================================================================================================================


def lambda_handler(event, context):

    #logger.info("log -- Event: %s " % json.dumps(event))

    try:

        expire_time = int(time.time()) - (int(os.environ['RETENTION'])*60)
        logger.info("expire_time = %s" % expire_time)

        #scan the ddb table to find expired records
        ddb = boto3.resource('dynamodb')
        table = ddb.Table(ACLMETATABLE)
        response = table.scan(FilterExpression=Attr('CreatedAt').lt(expire_time))

        # process each expired record
        for item in response['Items']:
            logger.info("deleting item: %s" %item)
            logger.info("HostIp %s" %item['HostIp'])
            HostIp = item['HostIp']
            try:
                logger.info('deleting netacl rule')
                delete_netacl_rule(item['NetACLId'], item['RuleNo'])
                
                # check if IP is also recorded in a fresh finding, don't remove IP from blacklist in that case
                response_nonexpired = table.scan( FilterExpression=Attr('CreatedAt').gt(expire_time) & Attr('HostIp').eq(HostIp) )
                if len(response_nonexpired['Items']) == 0:
                    logger.info('deleting ALB WAF ip entry')
                    waf_update_ip_set('alb', os.environ['ALB_IP_SET_ID'], HostIp)
                    logger.info('deleting CloudFront WAF ip entry')
                    waf_update_ip_set('cloudfront', os.environ['CLOUDFRONT_IP_SET_ID'], HostIp)
                
                logger.info('deleting dynamodb item')
                delete_ddb_rule(item['NetACLId'], item['CreatedAt'])

            except Exception as e:
                logger.error(e)
                logger.error('could not delete item')

        logger.info("Pruning Completed")

    except Exception as e:
        logger.error('something went wrong')
        raise
