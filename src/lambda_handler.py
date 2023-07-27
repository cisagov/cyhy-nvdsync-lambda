"""Simple AWS Lambda handler to verify functionality."""

# Standard Python Libraries
import asyncio
from datetime import datetime
import gzip
from io import BytesIO
import json
import logging
import os
from typing import List, Optional, Tuple
import urllib.parse
import urllib.request

# Third-Party Libraries
from beanie import Document, init_beanie
from boto3 import client as boto3_client
from botocore.exceptions import ClientError
from motor.motor_asyncio import AsyncIOMotorClient

default_log_level = "INFO"
logger = logging.getLogger()
logger.setLevel(default_log_level)

DEFAULT_NVD_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
NVD_FIRST_YEAR = 2002
DEFAULT_NVD_COLLECTION = "cves"

motor_client: AsyncIOMotorClient = None
ssm_client: boto3_client = None


class CVEDoc(Document):
    """Python class to represent a CVE Document."""

    id: str
    cvss_score: Optional[float]
    cvss_version: Optional[str]
    severity: Optional[int]

    class Settings:
        """Optional settings."""

        name = DEFAULT_NVD_COLLECTION
        validate_on_save = True

    async def save(self, *args, **kwargs):
        """Save the document to the database."""
        # Calculate severity based on CVSS version and score.

        if self.cvss_version == "2.0":
            if self.cvss_score == 10:
                self.severity = 4
            elif self.cvss_score >= 7.0:
                self.severity = 3
            elif self.cvss_score >= 4.0:
                self.severity = 2
            else:
                self.severity = 1
        elif self.cvss_version in ["3.0", "3.1"]:
            if self.cvss_score >= 9.0:
                self.severity = 4
            elif self.cvss_score >= 7.0:
                self.severity = 3
            elif self.cvss_score >= 4.0:
                self.severity = 2
            else:
                self.severity = 1
        await super().save(*args, **kwargs)


async def process_nvd(cve) -> str:
    """Add the provided CVE to the database and return its id."""
    # Fill fields for the CVE Documents from the given JSON files
    cve_id = cve["cve"]["CVE_data_meta"]["ID"]
    # Reject or remove CVEs that don't have baseMetricV2 or baseMetricV3 CVSS data
    if not any(k in cve["impact"] for k in ["baseMetricV2", "baseMetricV3"]):
        """If the CVE is in the database, it needs to be deleted from the database"""

        if await CVEDoc.find_one(CVEDoc.id == cve_id):
            print("x", end="")
            remove_cve_doc = CVEDoc(id=cve_id)
            await remove_cve_doc.delete()

            return cve_id

        else:
            print("x", end="")
            return cve_id

    else:
        version = "V3" if "baseMetricV3" in cve["impact"] else "V2"
        cvss_base_score = cve["impact"]["baseMetric" + version]["cvss" + version][
            "baseScore"
        ]
        cvss_version_temp = cve["impact"]["baseMetric" + version]["cvss" + version][
            "version"
        ]

        # Fill document fields with CVE data
        print(".", end="")

        print("Adding CVE: ", cve_id, " to database")

        cve_doc = CVEDoc(
            id=cve_id, cvss_score=float(cvss_base_score), cvss_version=cvss_version_temp
        )

        if not cve_id:
            raise ValueError("JSON does not look like valid CISA CVE data.")

        await cve_doc.save()
        return cve_doc.id


async def process_cve_json(json_stream) -> None:
    """Process the provided CVEs JSONs and update the database with its contents."""
    data = json.load(json_stream)

    if data.get("CVE_data_type") != "CVE":
        raise ValueError("JSON does not look like valid NVD CVE data.")

    tasks = [asyncio.create_task(process_nvd(cve)) for cve in data.get("CVE_Items", [])]

    for task in asyncio.as_completed(tasks):
        await task


async def process_urls(cve_urls, db) -> None:
    """Initialize beanie ODM and begin processing CVE URLs."""
    await init_beanie(database=motor_client[db], document_models=[CVEDoc])
    # Async for loop that processes each of the CVE URLs individually

    for cve_url in cve_urls:
        # We disable the bandit blacklist for the urllib.request.urlopen() function
        # because the URL is either the defaul (safe) URL or one provided in the
        # Lambda configuration so we can assume it is safe.
        retries = 0
        attempts = 10

        print("Connecting to socket from: ", cve_url)

        while True:
            try:
                socket = urllib.request.urlopen(cve_url)  # nosec B310
                break
            except (urllib.error.HTTPError, urllib.error.URLError) as err:
                logging.debug(
                    "Encountered a(n) %s exception while attempting to open socket from '%s'",
                    type(err).__name__,
                    cve_url,
                )
                retries += 1
                await asyncio.sleep(5)
                if retries <= attempts:
                    logging.warning(
                        "Performing retry %d/%d for '%s'", retries, attempts, cve_url
                    )
                else:
                    raise err

        buf = BytesIO(socket.read())
        f = gzip.GzipFile(fileobj=buf)
        await process_cve_json(f)


def generate_urls():
    """Return the NVD URLs for each year."""
    current_year = datetime.utcnow().year
    years = list(range(NVD_FIRST_YEAR, current_year + 1))
    return [DEFAULT_NVD_URL.format(**{"year": year}) for year in years]


def get_ssm_parameter(parameter_name: str) -> str:
    """Retrieve the value of the provided SSM Parameter Store key."""
    try:
        resp = ssm_client.get_parameter(Name=parameter_name, WithDecryption=True)
        return resp["Parameter"]["Value"]
    except ClientError:
        logging.error("Unable to retrieve SSM Parameter Store key: %s", parameter_name)
        raise


def build_mongodb_uri(
    ssm_username: str, ssm_password: str, ssm_host: str, ssm_port: str, ssm_auth_db: str
) -> Optional[str]:
    """Build a MongoDB database URI from the provided SSM Parameter Store keys."""
    uri = None
    try:
        # Ensure the username and password are safely encoded
        username = urllib.parse.quote_plus(get_ssm_parameter(ssm_username))
        password = urllib.parse.quote_plus(get_ssm_parameter(ssm_password))
        host = get_ssm_parameter(ssm_host)
        port = get_ssm_parameter(ssm_port)
        auth_db = get_ssm_parameter(ssm_auth_db)
        uri = f"mongodb://{username}:{password}@{host}:{port}/{auth_db}"
    except ClientError as client_err:
        logging.error("Unable to create MongoDB URI.")
        logging.exception(client_err)

    return uri


def handler(event, context) -> None:
    """Process the event and generate a response.

    The event should have a task member that is one of the supported tasks.

    :param event: The event dict that contains the parameters sent when the function
                  is invoked.
    :param context: The context in which the function is called.
    :return: The result of the action.
    """
    old_log_level = None

    global motor_client
    global ssm_client

    # Update the logging level if necessary
    new_log_level = os.environ.get("log_level", default_log_level).upper()
    if not isinstance(logging.getLevelName(new_log_level), int):
        logging.warning(
            "Invalid logging level %s. Using %s instead.",
            new_log_level,
            default_log_level,
        )
        new_log_level = default_log_level
    if logging.getLogger().getEffectiveLevel() != logging.getLevelName(new_log_level):
        old_log_level = logging.getLogger().getEffectiveLevel()
        logging.getLogger().setLevel(new_log_level)

    # Set up the SSM client if necessary
    if ssm_client is None:
        ssm_client = boto3_client("ssm")

    mongodb_uri_elements: List[Tuple[str, Optional[str]]] = []

    # This only runs from a CloudWatch scheduled event invocation
    trigger_source: Optional[str]
    trigger_type: Optional[str]
    if (
        (trigger_source := event.get("source")) is None
        or trigger_source != "aws.events"
    ) or (
        (trigger_type := event.get("detail-type")) is None
        or trigger_type != "Scheduled Event"
    ):
        logging.error("Invalid invocation event.")
        return

    for var in [
        "ssm_db_user",
        "ssm_db_pass",
        "ssm_db_host",
        "ssm_db_port",
        "ssm_db_authdb",
    ]:
        mongodb_uri_elements.append((var, os.environ.get(var)))

    # Check that we have all of the required variables
    if missing_variables := [k for k, v in mongodb_uri_elements if v is None]:
        logging.error("Missing required variables: %s", ",".join(missing_variables))
        return

    # Determine the database where the CVE data will be inserted
    write_db = get_ssm_parameter(os.environ.get("ssm_db_writedb", "ssm_db_authdb"))

    # Determine if a non-default CVEs JSON URL is being used
    nvd_urls = generate_urls()

    json_url = os.environ.get("json_url")
    if json_url is None:
        cve_json_urls = nvd_urls
    else:
        cve_json_urls = [json_url]

    # Determine if a non-default collection is being used
    db_collection = os.environ.get("target_collection")
    if db_collection is not None:
        CVEDoc.Settings.name = get_ssm_parameter(db_collection)

    # We disable mypy here because the variable is typed to have Optional[str] elements
    # but we verify that there are only str elements before this point.
    mongodb_uri = build_mongodb_uri(*[v for k, v in mongodb_uri_elements])  # type: ignore

    if mongodb_uri is None:
        logging.error("Unable to import KEV data.")
        return

    # Set up the Motor session if necessary
    if motor_client is None:
        motor_client = AsyncIOMotorClient(mongodb_uri)

    try:
        asyncio.get_event_loop().run_until_complete(
            process_urls(cve_json_urls, write_db)
        )
    except Exception as err:
        logging.error("Problem encountered while processing the CVEs JSON")
        logging.exception(err)

    if old_log_level is not None:
        logging.getLogger().setLevel(old_log_level)
