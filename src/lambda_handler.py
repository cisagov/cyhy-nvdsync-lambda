"""Simple AWS Lambda handler to verify functionality."""

# Standard Python Libraries
import asyncio
import json
import logging
import gzip
import os
from typing import List, Optional, Set, Tuple
import urllib.parse
import urllib.request
from datetime import datetime
from io import StringIO, BytesIO

# Third-Party Libraries
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
    
    id: str # CVE string
    cvss_score: float
    cvss_version: str
    severity: Optional [int]
    
    class Settings:
        """Optional settings."""
        
        validate_on_save = True
        
    def calculate_severity(self):
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

async def process_nvd(cve) -> str:
    """Add the provided CVE to the database and return its id."""
    cve_id = cve.get("cveID")
    
    
    if not cve_id:
        raise ValueError("JSON does not look like valid CISA CVE data.")

    cve_doc = CVEDoc(id=cve_id)
    await cve_doc.save()
    return cve_doc.id

            
            
async def process_cve_json(json_stream, target_db) -> None:
    """Process the provided CVEs JSONs and update the database with its contents."""
    await init_beanie(database=motor_client[target_db], document_models=[CVEDoc])
    data = json.load(json_stream)
    imported_cves = set()

    if data.get("CVE_data_type") != "CVE":
        raise ValueError("JSON does not look like valid NVD CVE data.")

    for entry in data.get("CVE_Items", []):
        # Fill fields for the CVE Documents from the given JSON files
        cve_id = entry["cve"]["CVE_data_meta"]["ID"]
        print(cve_id)
        version = "V3" if "baseMetricV3" in entry["impact"] else "V2"
        print(version)
        cvss_base_score = entry["impact"]["baseMetric" + version]["cvss" + version]["baseScore"]
        print(cvss_base_score)
        cvss_version_temp = entry["impact"]["baseMetric" + version]["cvss" + version]["version"]
        cve_doc_temp = CVEDoc(
                id=cve_id,
                cvss_score=cvss_base_score,
                cvss_version=cvss_version_temp
            )
            
        cve_doc_temp.calculate_severity()
            
        # Reject CVEs that don't have baseMetricV2 or baseMetricV3 CVSS data
        if not any(k in entry["impact"] for k in ["baseMetricV2", "baseMetricV3"]):
            
             # Make sure they are removed from our db.
            unscored_cve_doc = await CVEDoc.find_one(
                CVEDoc.id == cve_id,
                CVEDoc.cvss_score == float(cvss_base_score),
                CVEDoc.cvss_version == cvss_version_temp,
                CVEDoc.severity == cve_doc_temp.severity
            )
            
            await unscored_cve_doc.delete()
            print("x", end="")
        else:
            # Fill document fields with CVE data
            print(".", end="")
   
            entry_doc = CVEDoc(
                id = cve_id,
                cvss_score = float(cvss_base_score),
                cvss_version = cvss_version_temp,
                severity = cve_doc_temp.severity
            )
            
        
        tasks = [
            asyncio.create_task((process_nvd(entry_doc)))
            ]
            
    for task in asyncio.as_completed(tasks):
        nvd_cves = await task
        imported_cves.add(nvd_cves)
        
    print("\n\n")
    
    
async def process_url(url, db) -> None:
    socket = urllib.request.urlopen(url)
    buf = BytesIO(socket.read())
    f = gzip.GzipFile(fileobj=buf)
    await process_cve_json(f, db)
    

def generate_urls():
    """Returns the NVD URLs for each year."""
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
        for cve_urls in cve_json_urls:
            asyncio.run(process_url(cve_urls, write_db))
    except Exception as err:
        logging.error(
            "Problem encountered while processing the CVEs JSON at %s", cve_urls
        )
        logging.exception(err)  

    if old_log_level is not None:
        logging.getLogger().setLevel(old_log_level)
