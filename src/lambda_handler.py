"""Simple AWS Lambda handler to verify functionality."""

# Standard Python Libraries
import asyncio
from datetime import datetime
import gzip
from io import BytesIO
import json
import logging
import os
from typing import Optional

# Third-Party Libraries
import aiohttp
from beanie import Document, init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

default_log_level = "INFO"
logger = logging.getLogger()
logger.setLevel(default_log_level)

DEFAULT_NVD_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
NVD_FIRST_YEAR = 2002
DEFAULT_NVD_COLLECTION = "cves"

motor_client: AsyncIOMotorClient = None


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
    try:
        cve_id = cve["cve"]["CVE_data_meta"]["ID"]
    except KeyError:
        # JSON might be malformed, so we'll log what the CVE object looks like
        # and then raise an error
        logger.error("CVE object: %s", cve)
        raise ValueError("JSON does not look like valid NVD CVE data.")
    # All fields are there but 'ID' field is empty
    if not cve_id:
        raise ValueError("CVE ID is empty.")

    # Reject or remove CVEs that don't have baseMetricV2 or baseMetricV3 CVSS data
    if not any(k in cve["impact"] for k in ["baseMetricV2", "baseMetricV3"]):
        """If the CVE is in the database, it needs to be deleted from the database"""

        outdated_cve_doc = await CVEDoc.find_one(CVEDoc.id == cve_id)

        if outdated_cve_doc:
            print("x", end="")
            await outdated_cve_doc.delete()
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

        try:
            cve_doc = CVEDoc(
                id=cve_id,
                cvss_score=float(cvss_base_score),
                cvss_version=cvss_version_temp,
                severity=None,
            )
        except ValueError:
            logger.error("CVE object: %s", cve)
            raise ValueError("JSON does not look like valid NVD CVE data.")

        await cve_doc.save()

        return cve_doc.id


async def process_cve_json(json_stream) -> None:
    """Process the provided CVEs JSONs and update the database with its contents."""
    data = json.load(json_stream)

    if data.get("CVE_data_type") != "CVE":
        raise ValueError("JSON does not look like valid NVD CVE data.")

    tasks = [asyncio.create_task(process_nvd(cve)) for cve in data.get("CVE_Items", [])]

    await asyncio.gather(*tasks)

    # Show the time at which the JSON was processed
    print("Finished processing JSON at ", datetime.utcnow().isoformat())


async def unzip_and_process(content):
    """Unzip content and process it with process_cve_json()."""
    with gzip.GzipFile(fileobj=BytesIO(content)) as f:
        await process_cve_json(f)


async def fetch_url_content(session, url):
    """Fetch the content of the provided URL."""
    async with session.get(url) as response:
        return await response.read()


async def process_urls(cve_urls, db) -> None:
    """Initialize beanie ODM and begin processing CVE URLs."""
    await init_beanie(database=motor_client[db], document_models=[CVEDoc])

    async with aiohttp.ClientSession() as session:
        tasks = []

        for cve_url in cve_urls:
            attempts = 0
            retries = 10

            while True:
                try:
                    print("Before socket")
                    content = await fetch_url_content(session, cve_url)
                    tasks.append(asyncio.create_task(unzip_and_process(content)))
                    break
                except aiohttp.ClientError as err:
                    logging.debug(
                        "Encountered a(n) %s exception while attempting to fetch URL '%s'",
                        type(err).__name__,
                        cve_url,
                    )
                    attempts += 1
                    await asyncio.sleep(5)
                    if attempts <= retries:
                        logging.warning(
                            "Performing retry %d/%d for '%s'",
                            attempts,
                            retries,
                            cve_url,
                        )
                    else:
                        raise err
    await asyncio.gather(*tasks)


def generate_urls():
    """Return the NVD URLs for each year."""
    current_year = datetime.utcnow().year
    years = list(range(NVD_FIRST_YEAR, current_year + 1))
    return [DEFAULT_NVD_URL.format(**{"year": year}) for year in years]


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

    # Determine the database where the CVE data will be inserted
    write_db = "cyhy"

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
        CVEDoc.Settings.name = db_collection

    # We disable mypy here because the variable is typed to have Optional[str] elements
    # but we verify that there are only str elements before this point.
    # mongodb_uri = "mongodb://{}:{}@{}:{}/{}".format(*[v for k, v in mongodb_uri_elements])  # type: ignore
    mongodb_uri = "mongodb://mongo:27017/"

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
