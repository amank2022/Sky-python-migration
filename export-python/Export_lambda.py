import json
import os
import re
import uuid
from http import HTTPStatus
from urllib.parse import urlparse
import boto3

import psycopg2
import psycopg2.extras

from utils import (
    ExtractJTI,
    GetResposeDict,
    SkyflowAuthorization,
    GetJobDetail,
    ValidateAuthScheme,
    ValidateVaultId,
    logger,
    saveQuery,
    cursor,
    connection
)

source = "ExportQueryAPI"

reg_exp = "^s3://([^/]+)/(.*?([^/]+)/?)$"

applicationId = os.environ.get("APPLICATION_ID")
executionRoleArn = os.environ.get("EXECUTION_ROLE_ARN")
sparkSubmitParameters = os.environ.get("SPARK_SUBMIT_PARAMETERS")
entryPoint = os.environ.get("ENTRYPOINT")
logUri = os.environ.get("LOG_URI")
secrets = os.environ.get("SECRETS")
region = os.environ.get("REGION")

# create session of aws


def CheckVerificationNonce(querySecret, verificationNonce, destination, queryId, crossBucketRegion):

    s3_uri = urlparse(destination)
    
    bucketName = s3_uri.hostname
    print(bucketName)

    
    if len(s3_uri.path) != 0:
        nonceFilePath = s3_uri.path[1:] + "/query-" + queryId + "-nonce"
        
    else:
        nonceFilePath = "query-" + queryId + "-nonce"
        
    nonce_verification_role_arn = os.environ.get("NONCE_VERIFICATION_ROLE_ARN")
    logger.info(f"Bucket Name: {bucketName}, Nonce Filepath: {nonceFilePath}, Query Secret: {querySecret}, nonce_verification_role_arn: {nonce_verification_role_arn}, crossBucketRegion:{crossBucketRegion}")
    
    boto_sts=boto3.client('sts')
    stsresponse = boto_sts.assume_role(
        RoleArn=nonce_verification_role_arn,
        RoleSessionName='newsession',
        Tags=[
        {
            'Key': 'QuerySecret',
            'Value': querySecret
        },
        ],
        TransitiveTagKeys=[
            'QuerySecret'
        ]
        
    )

    # Save the details from assumed role into vars
    newsession_id = stsresponse["Credentials"]["AccessKeyId"]
    newsession_key = stsresponse["Credentials"]["SecretAccessKey"]
    newsession_token = stsresponse["Credentials"]["SessionToken"]

    try:
        s3 = boto3.resource(
            "s3",
            aws_access_key_id=newsession_id,
            aws_secret_access_key=newsession_key,
            aws_session_token=newsession_token,
            region_name=crossBucketRegion,
        )
    except Exception as err:
        logger.error(f"Got error on Verification Nonce: {err}")
        raise Exception(err)
        # return false, errors.New(err.Error())    
    
    print("-----------------",bucketName,nonceFilePath)
    object = s3.Object(bucketName, nonceFilePath)
    # object = s3.Object('ac-test-bucket-01', 'output/location/query-123456-nonce')
    destinationVerificationNonce = object.get()['Body'].read().decode('utf-8')
    print(f"source------- {verificationNonce}")
    print(f"destination------- {destinationVerificationNonce}")
    if destinationVerificationNonce == verificationNonce:
        return True

    return False


def TriggerEMRJob(query, queryId):

    entryPointArguments = [query, queryId, secrets, region]

    logger.info("Initiating TriggerEMRJob")
    client = boto3.client("emr-serverless")

    try:
        response = client.start_job_run(
            applicationId=applicationId,
            executionRoleArn=executionRoleArn,
            jobDriver={
                "sparkSubmit": {
                    "entryPoint": entryPoint,
                    "entryPointArguments": entryPointArguments,
                    "sparkSubmitParameters": sparkSubmitParameters,
                }
            },
            configurationOverrides={
                "monitoringConfiguration": {
                    "s3MonitoringConfiguration": {
                        "logUri": logUri
                    }
                }
            },
        )
    
    except Exception as err:
        logger.error(f"Failed to trigger EMR Job with error: {err}")
        raise Exception(err)
    
    return response.get('jobRunId')


def LogJob(queryId, jobId, queryStatus, requestId, query, destination, cross_bucket_region, jti, clientIp):
    logger.info("Initiating LogJob")

    statement = "UPDATE emr_job_details SET job_id=%s, query_status=%s  WHERE query_id=%s"

    logger.info(f"Updating record for jobId: {jobId} & requestId:{requestId}")

    try:
        cursor.execute(statement, (jobId, queryStatus, queryId))
        connection.commit()
        # cursor.close()
    
    except Exception:
        logger.error("Something went wrong while inserting into database.")
        message = "Something went wrong! Please contact Skyflow administrative team."
        raise Exception(message)

    logger.info(f"Successfully logged jobId: {jobId} & requestId:{requestId}")
    
    # return True


def lambda_handler(event, context):

    queryId = event.get("pathParameters").get("queryID")

    logger.info(f"Initiated {source}")
    print("QueryID: ", queryId)

    clientIpAddress = event.get("headers").get("X-Forwarded-For").split(",")[0]
    logger.info(f"Client IP address: {clientIpAddress}")

    jobDetail = GetJobDetail(queryId)
    
    if not jobDetail:
        logger.error(f"Failed to get job details for queryId: {queryId}")

        return GetResposeDict(
            HTTPStatus.NOT_FOUND, f"Failed to check record for queryId: {queryId}", {"QueryID": queryId}
        )
    print("jobDetail: ",jobDetail)
    if jobDetail.get("query_status") != "READY":
        logger.info("Job has already been started and cannot be triggered again.")

        return GetResposeDict(
            HTTPStatus.BAD_REQUEST,
            "Job has already been started and cannot be triggered again.",
            {"QueryID": queryId},
        )

    responseBody = {
        "queryId": queryId,
        "query": jobDetail.get("query"),
        "destinationBucket": jobDetail.get("destination"),
        "region": jobDetail.get("cross_bucket_region")
    }

    logger.info(
        f"""Successfully Executed query. \n
        {responseBody}"""
    )

    vaultId = event.get("pathParameters").get("vaultID")
    token = event.get("headers").get("Authorization")

    authSchemeValidation = ValidateAuthScheme(token)
    if not authSchemeValidation:
        return GetResposeDict(
            HTTPStatus.UNAUTHORIZED.value, "Auth Scheme not supported", responseBody
        )

    jti = ExtractJTI(token)
    if not jti:
        return GetResposeDict(
            HTTPStatus.FORBIDDEN.value, "Failed to extract jti", responseBody
        )

    validVaultIdValidation = ValidateVaultId(vaultId)

    if not validVaultIdValidation:
        return GetResposeDict(
            HTTPStatus.FORBIDDEN.value, "Invalid Vault ID", responseBody
        )

    authResponse = SkyflowAuthorization(token, jobDetail.get("query"), vaultId, queryId)
    # authResponse= {
    #     "level": "info",
    #     "msg": {
    #         "statusCode": 200,
    #         "requestId": "b9ee6ed4-5abc-9fe8-8303-95f4afe6b23f",
    #         "body": {"records": []},
    #     },
    #     "time": "2022-12-26T07:31:49.657081Z",
    #     "source": None,
    #     "statusCode": 200,
    #     "requestId": "b9ee6ed4-5abc-9fe8-8303-95f4afe6b23f",
    #     "body": {"records": []},
    # }

    if "error" in authResponse:
        return GetResposeDict(
            authResponse["statusCode"],
            authResponse["error"],
            responseBody,
            queryId=queryId,
        )

    if authResponse["statusCode"] != HTTPStatus.OK.value:
        return GetResposeDict(
            authResponse["statusCode"],
            authResponse["body"],
            responseBody,
            queryId=queryId,
        )

    logger.info(authResponse)
    logger.info(
        f"""skyflowRequestId: {authResponse["requestId"]},\n
        query: {jobDetail.get("query")},\n
        destinationBucket: {jobDetail.get("destination")},\n
        region: {jobDetail.get("cross_bucket_region")}"""
    )

    logger.info("Sucessfully Authorized")

    try:
        verified_nonce = CheckVerificationNonce(
            jobDetail.get("query_secret"),
            jobDetail.get("verification_nonce"),
            jobDetail.get("destination"),
            queryId,
            jobDetail.get("cross_bucket_region"),
        )
    
    except Exception as err:
        return GetResposeDict(
            HTTPStatus.UNAUTHORIZED, str(err), responseBody
        )

    if not verified_nonce:
        return GetResposeDict(
            HTTPStatus.FORBIDDEN.value, "Invalid Verification Nonce.", responseBody
        )

    logger.info(
        f"Triggering Spark job with args, query: {jobDetail.get('query')}, destination: {jobDetail.get('destination')}"
    )

    try:
        jobId = TriggerEMRJob(jobDetail.get("query"), queryId)
    
    except Exception as err:
        return GetResposeDict(
            HTTPStatus.INTERNAL_SERVER_ERROR, str(err), responseBody
        )

    queryStatus = "INITIATED"

    try:
        LogJob(
            queryId,
            jobId,
            queryStatus,
            authResponse.get("requestId"),
            jobDetail.get("query"),
            jobDetail.get("destination"),
            jobDetail.get("cross_bucket_region"),
            jti,
            clientIpAddress,
        )

    except Exception as err:
        return GetResposeDict(
            HTTPStatus.INTERNAL_SERVER_ERROR, str(err), responseBody
        )

    responseBody = {
        "queryId": queryId,
        "jobId": jobId,
        "queryStatus": queryStatus,
        "requestId": authResponse.get("requestId")
    }

    return GetResposeDict(
        HTTPStatus.OK.value, "Sucessfully executed ExportAPI.", responseBody
    )