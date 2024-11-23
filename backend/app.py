import logging
import re
import os
import csv
import io
from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import List
import motor.motor_asyncio
from presidio_analyzer import AnalyzerEngine
from bson import ObjectId
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from bson import ObjectId
from fastapi import Request

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Add CORSMiddleware to allow cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins to make requests
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],  # Allow all headers
)
# MongoDB client
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
client = motor.motor_asyncio.AsyncIOMotorClient(MONGODB_URI)
db = client.pii_database

class PiiData(BaseModel):
    id: str  # Add this line for the ID
    file_name: str
    pii_type: str
    pii_value: str


# Helper function to handle ObjectId serialization
def object_id_to_str(doc):
    if "_id" in doc and isinstance(doc["_id"], ObjectId):
        doc["_id"] = str(doc["_id"])
    return doc

# Enhanced rulebase with regex patterns for PII
rulebase = [([  # Rule-based regex patterns
    ("AGE", re.compile(r"\S+ years old|\S+\-years\-old|\S+ year old|\S+\-year\-old")),
    ("STREET_ADDRESS", re.compile(
        r'\d{1,4} [\w\s]{1,20} (?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|park|parkway|pkwy|circle|cir|boulevard|blvd)', re.IGNORECASE)),
    ("STREET_ADDRESS", re.compile(r'P\.? ?O\.? Box \d+', re.IGNORECASE)),
    ("GOVT_ID", re.compile(r'(?!000|666|333)0*(?:[0-6][0-9][0-9]|[0-7][0-6][0-9]|[0-7][0-7][0-2])[- ](?!00)[0-9]{2}[- ](?!0000)[0-9]{4}')),
    ("DISEASE", re.compile(r"diabetes|cancer|HIV|AIDS|Alzheimer's|Alzheimer|heart disease", re.IGNORECASE)),
    ("NORP", re.compile(r"upper class|middle class|working class|lower class", re.IGNORECASE)),
    ("BIRTH_DEATH_DATE", re.compile(
        r'born (?:(?<!\:)(?<!\:\d)[0-3]?\d(?:st|nd|rd|th)?\s+(?:of\s+)?(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)|(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)\s+(?<!\:)(?<!\:\d)[0-3]?\d(?:st|nd|rd|th)?)(?:\,)?\s*(?:\d{4})?|[0-3]?\d[-\./][0-3]?\d[-\./]\d{2,4}', re.IGNORECASE)),
    ("PHONE", re.compile(r'''((?:(?<![\d-])(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]?\d{4}))''', re.IGNORECASE)),
], 1)]

# Function to find PII
def find_pii(text: str, file_name: str):
    pii_data = []
    logger.info(f"Scanning file '{file_name}' for PII...")
    for category, pattern in rulebase[0][0]:
        matches = pattern.findall(text)
        for match in matches:
            pii_data.append({"file_name": file_name, "pii_type": category, "pii_value": match})
    return pii_data


# Initialize Presidio Analyzer
analyzer = AnalyzerEngine()

# Create scanML endpoint
class PiiData(BaseModel):
    id: str  # ID of the PII entity (could be generated from MongoDB)
    file_name: str  # Name of the file from which PII was extracted
    pii_type: str  # Type of PII (e.g., EMAIL_ADDRESS)
    pii_value: str  # Extracted PII value

@app.post("/scanML/", response_model=List[PiiData])
async def scan_pii(file: UploadFile = File(...)):
    logger.info(f"Received file '{file.filename}' for scanning.")

    # Determine the file type and extract text accordingly
    if file.filename.endswith('.txt'):
        text = (await file.read()).decode("utf-8")
    elif file.filename.endswith('.pdf'):
        text = extract_text_from_pdf(file)
    elif file.filename.endswith('.docx'):
        text = extract_text_from_docx(file)
    elif file.filename.endswith('.csv'):
        text = extract_text_from_csv(file)
    else:
        raise HTTPException(status_code=400, detail="Unsupported file type")

    logger.debug("Extracted text length: %d characters", len(text))
    
    # Scan for PII using Presidio
    results = analyzer.analyze(text=text, language='en')
    
    logger.info("PII extraction completed. Number of entities found: %d", len(results))
    
    if not results:
        logger.info(f"No PII found in file '{file.filename}'.")
        return []  # Return empty list if no PII found

    # Prepare PII data for insertion into the database and response
    pii_data_list = []
    
    for result in results:
        entity_data = {
            "id": str(result.start),  # You can generate a unique ID here if needed
            "file_name": file.filename,  # Store filename for reference
            "pii_type": result.entity_type,  # Use entity type for 'pii_type'
            "pii_value": text[result.start:result.end],  # Use extracted text for 'pii_value'
        }
        pii_data_list.append(PiiData(**entity_data))  # Create a PiiData instance

    logger.info(f"PII found in file '{file.filename}', saving to database.")
    
    # Save to database if PII found using db.pii_data.insert_many()
    await db.pii_data.insert_many([data.dict() for data in pii_data_list])  # Insert as dicts
    
    return pii_data_list  # Return the prepared PII data directly

# Function to extract text from CSV
def extract_text_from_csv(file: UploadFile):
    content = file.file.read().decode("utf-8")
    reader = csv.reader(io.StringIO(content))
    rows = []
    for row in reader:
        rows.append(" ".join(row))  # Combine all columns in a row into a single string
    return "\n".join(rows)  # Combine all rows into a single text block

# Placeholder for extracting text from PDFs
def extract_text_from_pdf(file: UploadFile):
    raise NotImplementedError("PDF extraction logic not implemented")

# Placeholder for extracting text from DOCX
def extract_text_from_docx(file: UploadFile):
    raise NotImplementedError("DOCX extraction logic not implemented")

# Helper function to serialize MongoDB ObjectId
# Helper function to serialize MongoDB ObjectId
def serialize_mongo_record(record):
    if "_id" in record:
        record["id"] = str(record["_id"])  # Map ObjectId to 'id'
        del record["_id"]  # Optionally remove the original _id field
    return record

# Endpoint to scan files for PII using regex
@app.post("/scanFile")
async def scan_file(file: UploadFile = File(...)):
    logger.info(f"Received file '{file.filename}' for scanning.")

    # Determine the file type and extract text accordingly
    if file.filename.endswith('.txt'):
        text = (await file.read()).decode("utf-8")
    elif file.filename.endswith('.pdf'):
        text = extract_text_from_pdf(file)
    elif file.filename.endswith('.docx'):
        text = extract_text_from_docx(file)
    elif file.filename.endswith('.csv'):
        text = extract_text_from_csv(file)
    else:
        raise HTTPException(status_code=400, detail="Unsupported file type")

    # Scan for PII
    pii_data = find_pii(text, file.filename)
    if not pii_data:
        logger.info(f"No PII found in file '{file.filename}'.")
        return []  # Return empty list if no PII found

    # Save to database if PII found
    # Save to database if PII found
    logger.info(f"PII found in file '{file.filename}', saving to database.")
    result = await db.pii_data.insert_many(pii_data)
    saved_data = await db.pii_data.find({"_id": {"$in": result.inserted_ids}}).to_list(len(result.inserted_ids))
    return [serialize_mongo_record(record) for record in saved_data]

@app.get("/retrieveAll", response_model=List[PiiData])
async def retrieve_all():
    try:
        # Fetch all records from the PII collection
        pii_cursor = db.pii_data.find()
        pii_data = await pii_cursor.to_list(length=1000)  # Fetch up to 1000 records

        # Serialize each record
        serialized_pii_data = [serialize_mongo_record(record) for record in pii_data]

        return serialized_pii_data
    except Exception as e:
        # Handle potential errors
        raise HTTPException(status_code=500, detail=f"Error fetching PII data: {str(e)}")

# Other endpoints (scanML, retrieveAll, etc.) should apply the same logic for serializing ObjectId.
# Each database fetch response must include `object_id_to_str`.

@app.delete("/delete/")
async def delete_pii(request: Request):
    try:
        delete_request = await request.json()
        file_name = delete_request.get("file_name")
        pii_value = delete_request.get("pii_value")
        
        logger.info(f"Received request to delete: file_name={file_name}, pii_value={pii_value}")

        if not file_name or not pii_value:
            raise HTTPException(status_code=400, detail="file_name and pii_value are required.")

        query = {
            "file_name": file_name,
            "pii_value": pii_value
        }

        result = await db.pii_data.delete_one(query)

        if result.deleted_count == 1:
            logger.info(f"Deleted PII record with file name '{file_name}' and value '{pii_value}'.")
            return {"detail": "Record deleted successfully."}
        else:
            raise HTTPException(status_code=404, detail="Record not found.")
    except Exception as e:
        logger.error(f"Error deleting record with file name '{file_name}' and value '{pii_value}': {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error deleting record: {str(e)}")

@app.delete("/deleteAll")
async def delete_all_pii():
    try:
        result = await db.pii_data.delete_many({})  # Delete all records
        logger.info(f"Deleted {result.deleted_count} PII records.")
        return {"detail": f"Deleted {result.deleted_count} records successfully."}
    except Exception as e:
        logger.error(f"Error deleting all PII records: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error deleting records: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
