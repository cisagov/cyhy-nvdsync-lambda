"""Simple AWS Lambda handler to verify functionality."""

# Standard Python Libraries
import asyncio
import json
import logging
import os
from typing import List, Optional, Set, Tuple
import urllib.parse
import urllib.request
from datetime import datetime
from dateutil import tz

# Third-Party Libraries
from beanie import Document, init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

default_log_level = "INFO"
logger = logging.getLogger()
logger.setLevel(default_log_level)

DEFAULT_NVD_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
NVD_FIRST_YEAR = 2002

motor_client: AsyncIOMotorClient = None


class CVEDoc(Document):
    """Python class that represents a cve document."""

    id: str
    cvss_score: float
    cvss_version: str
    severity: int

    class Settings:
        """Optional settings."""

        # Default collection to use
        name = "cves"
        validate_on_save = True
        
async def process_cve(cve) -> str:
    """Add the provided CVE to the database and return its id."""
    cve_id = cve.get("cveID")
    if not cve_id:
        raise ValueError("JSON does not look like valid CISA CVE data.")

    cve_doc = CVEDoc(id=cve_id)
    await cve_doc.save()
    return cve_doc.id

def utcnow():
    """Returns a timezone-aware datetime object with the current time in UTC."""
    return datetime.now(tz.tzutc())

def generate_urls():
    """Returns the NVD URLs for each year."""
    current_year = utcnow().year
    years = range(NVD_FIRST_YEAR, current_year + 1)
    return [DEFAULT_NVD_URL.format(**{"year": year}) for year in years]

async def process_cve_json(json_urls, target_db) -> None:
    """Process the provided CVEs JSONs and update the database with its contents."""
    await init_beanie(database=motor_client[target_db], document_models=[CVEDoc])
    
    imported_cves = set()

    # We disable the bandit blacklist for the urllib.request.urlopen() function
    # because the URL is either the defaul (safe) URL or one provided in the
    # Lambda configuration so we can assume it is safe.
    for json_url in json_urls:
        
        with urllib.request.urlopen(json_url) as response:  # nosec B310
            if response.status != 200:
                raise Exception("Failed to retrieve CISA CVE JSON.")

            nvd_json = json.loads(response.read().decode("utf-8"))

            tasks = [
                asyncio.create_task(process_cve(cve)) for cve in nvd_json["vulnerabilities"]
            ]

            for task in asyncio.as_completed(tasks):
                nvd_cve = await task
                imported_cves.add(nvd_cve)



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
        
    # mongodb_uri_elements: List[Tuple[str, Optional[str]]] = []

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

    # Build a list of tuples to validate and create the MongoDB URI
    # for var in [
    #     "db_user",
    #     "db_pass",
    #     "db_host",
    #     "db_port",
    #     "db_authdb",
    # ]:
    #     mongodb_uri_elements.append((var, os.environ.get(var)))

    # Check that we have all of the required variables
    # if missing_variables := [k for k, v in mongodb_uri_elements if v is None]:
    #     logging.error("Missing required variables: %s", ",".join(missing_variables))
    #     return

    # Determine the database where the CVE data will be inserted
    # write_db = os.environ.get("db_writedb", "db_authdb")
    write_db = "cyhy"

    # Determine if a non-default CVEs JSON URL is being used
    nvd_urls = generate_urls()
    for nvd_url in nvd_urls:
        cve_json_url = os.environ.get("json_url", nvd_url)

    # Determine if a non-default collection is being used
    db_collection = os.environ.get("target_collection")
    if db_collection is not None:
        CVEDoc.Settings.name = db_collection

    # We disable mypy here because the variable is typed to have Optional[str] elements
    # but we verify that there are only str elements before this point.
    # mongodb_uri = "mongodb://{}:{}@{}:{}/{}".format(*[v for k, v in mongodb_uri_elements])  # type: ignore
    mongodb_uri = "mongodb://mongo:27017/"

    # Set up the Motor session if necessary
    if motor_client is None:
        motor_client = AsyncIOMotorClient(mongodb_uri)

    try:
        asyncio.run(process_cve_json(cve_json_url, write_db))
    except Exception as err:
        logging.error(
            "Problem encountered while processing the CVEs JSON at %s", cve_json_url
        )
        logging.exception(err)  

    if old_log_level is not None:
        logging.getLogger().setLevel(old_log_level)
