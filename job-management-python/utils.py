import json
import logging
import os
from datetime import datetime
from http import HTTPStatus

import jwt
import psycopg2
import psycopg2.extras
import requests
from psycopg2.extras import RealDictCursor
from pythonjsonlogger import jsonlogger

# vaultUrl = os.environ.get("VAULT_URL").strip()
managementUrl = os.environ.get("MANAGEMENT_URL").strip()
validVaultIds = os.environ.get("VALID_VAULT_IDS").split(",")

connection = psycopg2.connect(
    user=os.environ.get("DB_USER"),
    password=os.environ.get("DB_PASSWORD"),
    host=os.environ.get("DB_HOST"),
    port=os.environ.get("DB_PORT"),
    database=os.environ.get("DB_NAME"),
)


cursor = connection.cursor(cursor_factory=RealDictCursor)


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(
            log_record,
            record,
            message_dict,
        )
        if not log_record.get("timestamp"):
            now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            log_record["time"] = now
        if log_record.get("level"):
            log_record["level"] = log_record["level"].lower()
        else:
            log_record["level"] = record.levelname.lower()


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter = CustomJsonFormatter("%(level)s %(msg)s %(time)s %(source)s")
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)
logger.propagate = False


def ValidateAuthScheme(token):
    """
    It will check Auth scheme is Bearer or not
    Args
       token(str): It is a auth token
    Return:
       if scheme is correct it will return True else False
    """
    logger.info("Initiating ValidateAuthScheme")
    authScheme = token.split(" ")[0]

    if authScheme != "Bearer":
        return False

    return True


def ExtractJTI(authToken):
    """
    It extract jti from auth tokem
    Args
       authToken(str): It is a auth token
    Return:
       jti if able to decode it otherwise None
    """
    logger.info("Initiating ExtractJTI")
    tokenString = authToken.split(" ")[1]
    try:
        token = jwt.decode(tokenString, verify=False)
        jti = token["jti"]
        logger.info("Successfully extracted JTI")
    except Exception:
        return None

    return jti


def ValidateVaultId(vaultId):
    """
    It validate vault id is from define whitelist or not
    Args
       vaultId(str): It is vault id
    Return:
       True if valid id pass otherwise False
    """
    logger.info("Initiating ValidateVaultId")
    logger.info(f"vaultId:{vaultId}, validVaultIds:{validVaultIds}")

    for validVaultId in validVaultIds:
        if vaultId == validVaultId:
            return True

    return False


def SkyflowAuthorization(token, query, vaultId, queryId):
    """
    Make a call to skyflow control plan and check authentication
    or authorization for given user.
    Args
       token(str): It is token given in header
       query(str): query to run on data
       vaultId(str): It is vault id
       queryId(str): It is queryId for which setup hasbeen done.
    Return:
       It will return dict { "statusCode": '', "requestId": '', "body": ''}
       if user don't have permission/any error in query then "statusCode"
       will be !200
    """
    logger.info("Initiating SkyflowAuthorization")

    if len(query) == 0:
        logger.error(f"Got invalid query: {queryId}")
        return {"statusCode": HTTPStatus.UNAUTHORIZED.value, "error": "Invalid Query"}

    payload = json.dumps({"query": query})

    url = vaultUrl + "/v1/vaults/" + vaultId + "/query"

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": token,
    }

    logger.info("Initiating Skyflow Request for Authorization")
    response = requests.post(url, headers=headers, data=payload)
    responseBody = response.json()

    if "error" in responseBody:

        logger.error(
            f"""
            Unable/Fail to call Skyflow API status code: {response.status_code} and \n
            message: {responseBody.get('error').get('message', 'Got error on Skyflow Authorization')}"""    # noqa: E501
        )
        return {
            "statusCode": responseBody.get("error").get(
                "http_code", HTTPStatus.INTERNAL_SERVER_ERROR.value
            ),
            "error": responseBody.get("error").get(
                "message", "Got error on Skyflow Authorization"
            ),
        }

    if response.status_code != HTTPStatus.OK.value:
        logger.error(
            f"""
            Unable/Fail to call Skyflow API status code: {response.status_code} and \n
            message: {responseBody}"""
        )

    return {
        "statusCode": response.status_code,
        "requestId": response.headers["x-request-id"],
        "body": responseBody,
    }

def SkyflowAuthJobManageAPI(token, vaultId, queryId):
    """
    Make a call to skyflow control plan and check authentication
    or authorization for given user.
    Args
       token(str): It is token given in header
       vaultId(str): It is vault id
       queryId(str): It is queryId for which setup hasbeen done.
    Return:
       It will return dict { "statusCode": '', "requestId": '', "body": ''}
       if user don't have permission/any error in query then "statusCode"
       will be !200
    """
    logger.info("Initiating SkyflowAuthorization for Job Management")

    url = managementUrl + "/v1/vaults/" + vaultId

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": token,
    }

    logger.info("Initiating Skyflow Request for Authorization")
    response = requests.get(url, headers=headers)
    responseBody = response.json()

    if "error" in responseBody:

        logger.error(
            f"""
            Unable/Fail to call Skyflow API status code: {response.status_code} and \n
            message: {responseBody.get('error').get('message', 'Got error on Skyflow Authorization')}"""    # noqa: E501
        )
        return {
            "statusCode": responseBody.get("error").get(
                "http_code", HTTPStatus.INTERNAL_SERVER_ERROR.value
            ),
            "error": responseBody.get("error").get(
                "message", "Got error on Skyflow Authorization"
            ),
        }

    if response.status_code != HTTPStatus.OK.value:
        logger.error(
            f"""
            Unable/Fail to call Skyflow API status code: {response.status_code} and \n
            message: {responseBody}"""
        )

    return {
        "statusCode": response.status_code,
        "requestId": response.headers["x-request-id"],
        "body": responseBody,
    }


def GetResposeDict(statusCode, message, body, **extra):
    data = {"body": body, "message": message}
    data.update(extra)
    responseDict = {"statusCode": statusCode, "body": json.dumps(data)}
    return responseDict


def GetJobDetail(queryId):
    logger.info("Initiating GetJobDetail")

    select_query = "SELECT query_id, COALESCE(query_secret,'') as query_secret, " \
                    "COALESCE(job_id, '') as job_id, query_status, request_id, " \
                    "query, destination, jti, verification_nonce, " \
                    "COALESCE(cross_bucket_region, %s) as cross_bucket_region FROM " \
                    "emr_job_details WHERE query_id=%s"

    cursor.execute(select_query, (os.environ.get("REGION"), queryId))
    data = cursor.fetchone()

    return data


def saveQuery(
    queryId,
    query,
    querySecret,
    requestId,
    destination,
    crossBucketRegion,
    verificationNonce,
    queryStatus,
    clientIpAddress,
    jti,
):

    insert_query = "INSERT INTO emr_job_details (query_id, query, query_secret, " \
                    "request_id, destination, cross_bucket_region, " \
                    "verification_nonce, query_status, client_ip, jti) " \
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"

    cursor.execute(
        insert_query,
        (
            queryId,
            query,
            querySecret,
            requestId,
            destination,
            crossBucketRegion,
            verificationNonce,
            queryStatus,
            clientIpAddress,
            jti,
        ),
    )
    connection.commit()
