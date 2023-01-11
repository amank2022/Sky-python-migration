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

managementUrl = os.environ.get("MANAGEMENT_URL")
applicationId = os.environ.get("APPLICATION_ID")

source = "JobManagementAPI"

def CancelEMRJob(jobId):
    logger.info("Initiating CancelEMRJob")
    client = boto3.client('emr-serverless')

    try:
        client.cancel_job_run(
            applicationId=applicationId,
            jobRunId=jobId
        )

    except Exception as err:
        logger.error(f"Failed to Cancel EMR Job with error: {err}")
        raise Exception(err)

    # return response.get('jobRunId')
    

def lambda_handler(event, context):
    queryId = event.get("pathParameters").get("queyID")

    logger.info(f"Initiated {source}")
    print("QueryID: ", queryId)

    clientIpAddress = event.get("headers").get("X-Forwarded-For").split(",")[0]
    logger.info(f"Client IP address: {clientIpAddress}")

    vaultId = event.get("pathParameters").get("vaultID")
    token = event.get("headers").get("Authorization")

    logger.Info(f"Checking record for queryId: {queryId}")

    jobDetail = GetJobDetail(queryId)
    if not jobDetail:
        logger.error(f"Failed to get job details for queryId: {queryId}")

        return GetResposeDict(
            HTTPStatus.NOT_FOUND, "Failed to get job details.", {"QueryID: ", queryId}
        )
    
    logger.info("Successfully Executed query")

    responseBody = {
        "queryId": queryId,
        "jobId": jobDetail.get("job_id")
    }

    authSchemeValidation = ValidateAuthScheme(token)
    if not authSchemeValidation:
        return GetResposeDict(
            HTTPStatus.UNAUTHORIZED.value, "Auth Scheme not supported", responseBody
        )

    jti = ExtractJTI(token)
    if not jti:
        return GetResposeDict(
            HTTPStatus.FORBIDDEN.value, "Failed to extract jti.", responseBody
        )

    validVaultIdValidation = ValidateVaultId(vaultId)

    if not validVaultIdValidation:
        return GetResposeDict(
            HTTPStatus.FORBIDDEN.value, "Invalid Vault ID.", responseBody
        )

    authResponse = SkyflowAuthorization(token, jobDetail.get("query"), vaultId, queryId)

    if "error" in authResponse:
        return GetResposeDict(
            authResponse["statusCode"],
            authResponse["error"],
            responseBody
        )

    if authResponse["statusCode"] != HTTPStatus.OK.value:
        return GetResposeDict(
            authResponse["statusCode"],
            authResponse["body"],
            responseBody
        )

    logger.info(authResponse)
    logger.info(
        f"""skyflowRequestId: {authResponse["requestId"]},\n
        query: {jobDetail.get("query")},\n
        destinationBucket: {jobDetail.get("destination")},\n
        region: {jobDetail.get("cross_bucket_region")}"""
    )

    logger.info("Sucessfully Authorized")


    if event.get("httpMethod") == "GET":
        responseBody = responseBody = {
            "queryId": queryId,
            "jobId": jobDetail.get("job_id"),
            "queryStatus": jobDetail.get("query_status"),
            "requestId": jobDetail.get("request_id"),
        }
        # return {"statusCode": 200, "body": json.dumps(responseBody)}
    
    if event.get("httpMethod") == "DELETE":
        if jobDetail.get("query_status").upper() == "SUCCESS" or jobDetail.get("query_status").upper() == "FAILURE":
            return GetResposeDict(
                HTTPStatus.BAD_REQUEST,
                f"Job for jobId:{jobDetail.get('job_id')} is already completed.",
                responseBody
            )

        if jobDetail.get("query_status").upper() == "CANCELLING" or jobDetail.get("query_status").upper() == "CANCELLED":
            return GetResposeDict(
                HTTPStatus.BAD_REQUEST,
                f"Job for jobId:{jobDetail.get('job_id')} is already cancelled.",
                responseBody
            )

        if jobDetail.get("query_status").upper() == "READY":
            message = f"Trying to update query status for queryId: {queryId}"
            logger.info(message)    

            statement = "UPDATE emr_job_details SET query_status=%s  WHERE query_id=%s"

            try:
                cursor.execute(statement, ("CANCELLED", queryId))
                connection.commit()
                cursor.close()
            
            except Exception:
                message = f"Failed to update record for queryId: %v with error: {queryId}" 
                logger.error(message)

            message = f"Successfully cancelled Job for queryId: {queryId}"

            return GetResposeDict(
                HTTPStatus.BAD_REQUEST,
                message,
                responseBody
            )
        try:
            CancelEMRJob(jobDetail.get("job_id"))

        except Exception as err:
            return GetResposeDict(
                HTTPStatus.INTERNAL_SERVER_ERROR, err, responseBody
            )

        logger.info("Successfully cancelled job")

        responseBody = responseBody = {
            "queryId": queryId,
            "jobId": jobDetail.get("job_id"),
            "requestId": jobDetail.get("request_id"),
            "message": "Successfully deleted",
        }

    return {"statusCode": 200, "body": json.dumps(responseBody)}
