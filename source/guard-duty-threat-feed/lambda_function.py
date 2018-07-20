#!/usr/bin/python
# -*- coding: utf-8 -*-
#########################################################################################
# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.               #
#                                                                                       #
# Permission is hereby granted, free of charge, to any person obtaining a copy of this  #
# software and associated documentation files (the "Software"), to deal in the Software #
# without restriction, including without limitation the rights to use, copy, modify,    #
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to    #
# permit persons to whom the Software is furnished to do so.                            #
#                                                                                       #
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,   #
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A         #
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT    #
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION     #
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE        #
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                                #
#########################################################################################

import boto3
import logging
import json
import hashlib
import hmac
import httplib
import urllib
import time
import traceback
import email
from botocore.vendored import requests
from datetime import datetime
from os import environ

def send_response(event, context, responseStatus, responseData, resourceId, reason=None):
    logging.getLogger().debug("send_response - Start")

    responseUrl = event['ResponseURL']
    logging.getLogger().debug(responseUrl)

    cw_logs_url = "https://console.aws.amazon.com/cloudwatch/home?region=%s#logEventViewer:group=%s;stream=%s"%(context.invoked_function_arn.split(':')[3], context.log_group_name, context.log_stream_name)
    logging.getLogger().debug("Logs: cw_logs_url")

    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = reason or ('See the details in CloudWatch Logs: ' +  cw_logs_url)
    responseBody['PhysicalResourceId'] = resourceId
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = False
    responseBody['Data'] = responseData

    json_responseBody = json.dumps(responseBody)

    logging.getLogger().debug("Response body:\n" + json_responseBody)

    headers = {
        'content-type' : '',
        'content-length' : str(len(json_responseBody))
    }

    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        logging.getLogger().debug("Status code: " + response.reason)

    except Exception as error:
        logging.getLogger().error("send(..) failed executing requests.put(..): " + str(error))

    logging.getLogger().debug("send_response - End")

def lambda_handler(event, context):
    responseStatus = 'SUCCESS'
    reason = None
    responseData = {}
    result = {
        'statusCode': '200',
        'body':  {'message': 'success'}
    }

    try:
        #------------------------------------------------------------------
        # Set Log Level
        #------------------------------------------------------------------
        global log_level
        log_level = str(environ['LOG_LEVEL'].upper())
        if log_level not in ['DEBUG', 'INFO','WARNING', 'ERROR','CRITICAL']:
            log_level = 'ERROR'
        logging.getLogger().setLevel(log_level)

        #------------------------------------------------------------------
        # Read inputs parameters
        #------------------------------------------------------------------
        logging.getLogger().info(event)
        request_type = event['RequestType'].upper()  if ('RequestType' in event) else ""
        logging.getLogger().info(request_type)

        #----------------------------------------------------------
        # Extra check for DELETE events
        #----------------------------------------------------------
        if 'DELETE' in request_type:
            if 'ResponseURL' in event:
                send_response(event, context, responseStatus, responseData, event['LogicalResourceId'], reason)

            return json.dumps(result)

        #------------------------------------------------------------------
        # Set query parameters
        #------------------------------------------------------------------
        queryType = '/view/iocs?'
        query = {
            'startDate' : int(time.time()) - (int(environ['DAYS_REQUESTED'])*86400),
            'endDate' : int(time.time())
        }

        #------------------------------------------------------------------
        # Query 3rd Party service
        #------------------------------------------------------------------
        #Get Public and Private access key
        public_key = None
        private_key = None
        ssm = boto3.client('ssm')
        response = ssm.get_parameters(Names=[environ['PUBLIC_KEY'], environ['PRIVATE_KEY']], WithDecryption = True)
        for p in response['Parameters']:
            if p['Name'] == environ['PUBLIC_KEY']:
                public_key = str(p['Value'])
            elif p['Name'] == environ['PRIVATE_KEY']:
                private_key = str(p['Value'])

        #Create Query
        enc_q = queryType + urllib.urlencode(query) + '&format=csv'

        #Generate proper accept_header for requested indicator type
        accept_header = 'text/csv'

        #Generate Hash for Auth
        timeStamp = email.Utils.formatdate(localtime=True)
        data = enc_q + '2.6' + accept_header + unicode(timeStamp)
        hashed = hmac.new(private_key, data, hashlib.sha256)

        headers = {
            'Accept': accept_header,
            'Accept-Version': '2.6',
            'X-Auth': public_key,
            'X-Auth-Hash': hashed.hexdigest(),
            'X-App-Name': 'mysight-api',
            'Date': timeStamp
        }

        #Get dataset
        conn = httplib.HTTPSConnection('api.isightpartners.com')
        conn.request('GET', enc_q, '', headers)
        response = conn.getresponse()
        result = {
            'statusCode': str(response.status),
            'body':  {'message': str(response.reason)}
        }
        logging.getLogger().debug(str(result))

        #------------------------------------------------------------------
        # Read Content
        #------------------------------------------------------------------
        timeStamp = datetime.now()
        fileName = "/tmp/iSIGHT_%s_%s_days.csv"%(timeStamp.strftime("%Y%m%d-%H%M%S"), environ['DAYS_REQUESTED'])
        with open(fileName, 'wb') as f:
            f.write(response.read())
            f.close()

        #------------------------------------------------------------------
        # Upload to S3
        #------------------------------------------------------------------
        s3 = boto3.client('s3')
        outputFileName = "iSIGHT/%s_%s_days.csv"%(timeStamp.strftime("%Y%m%d-%H%M%S"), environ['DAYS_REQUESTED'])
        s3.upload_file(fileName, environ['OUTPUT_BUCKET'], outputFileName, ExtraArgs={'ContentType': "application/CSV"})

        #------------------------------------------------------------------
        # Guard Duty
        #------------------------------------------------------------------
        location = "https://s3.amazonaws.com/%s/%s"%(environ['OUTPUT_BUCKET'], outputFileName)
        name = "TF-%s"%timeStamp.strftime("%Y%m%d")
        guardduty = boto3.client('guardduty')
        response = guardduty.list_detectors()

        if len(response['DetectorIds']) == 0:
            raise Exception('Failed to read GuardDuty info. Please check if the service is activated')

        detectorId = response['DetectorIds'][0]
        try:
            response = guardduty.create_threat_intel_set(
                Activate=True,
                DetectorId=detectorId,
                Format='FIRE_EYE',
                Location=location,
                Name=name
            )

        except Exception as error:
            if "name already exists" in error.message:
                found = False
                response = guardduty.list_threat_intel_sets(DetectorId=detectorId)
                for setId in response['ThreatIntelSetIds']:
                    response = guardduty.get_threat_intel_set(DetectorId=detectorId, ThreatIntelSetId=setId)
                    if (name == response['Name']):
                        found = True
                        response = guardduty.update_threat_intel_set(
                            Activate=True,
                            DetectorId=detectorId,
                            Location=location,
                            Name=name,
                            ThreatIntelSetId=setId
                        )
                        break

                if not found:
                    raise

            elif "AWS account limits" in error.message:
                #--------------------------------------------------------------
                # Limit reached. Try to rotate the oldest one
                #--------------------------------------------------------------
                oldestDate = None
                oldestID = None
                response = guardduty.list_threat_intel_sets(DetectorId=detectorId)
                for setId in response['ThreatIntelSetIds']:
                    response = guardduty.get_threat_intel_set(DetectorId=detectorId, ThreatIntelSetId=setId)
                    tmpName = response['Name']

                    if tmpName.startswith('TF-'):
                        setDate = datetime.strptime(tmpName.split('-')[-1], "%Y%m%d")
                        if oldestDate == None or setDate < oldestDate:
                            oldestDate = setDate
                            oldestID = setId

                if oldestID != None:
                    response = guardduty.update_threat_intel_set(
                        Activate=True,
                        DetectorId=detectorId,
                        Location=location,
                        Name=name,
                        ThreatIntelSetId=oldestID
                    )
                else:
                    raise

            else:
                raise

        #------------------------------------------------------------------
        # Update result data
        #------------------------------------------------------------------
        result = {
            'statusCode': '200',
            'body':  {'message': "You requested: %s day(s) of /view/iocs indicators in CSV"%environ['DAYS_REQUESTED']}
        }

    except Exception as error:
        logging.getLogger().error(str(error))
        responseStatus = 'FAILED'
        reason = error.message
        result = {
            'statusCode': '500',
            'body':  {'message': error.message}
        }

    finally:
        #------------------------------------------------------------------
        # Send Result
        #------------------------------------------------------------------
        if 'ResponseURL' in event:
            send_response(event, context, responseStatus, responseData, event['LogicalResourceId'], reason)

        return json.dumps(result)
