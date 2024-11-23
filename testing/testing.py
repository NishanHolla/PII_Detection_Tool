import os
import pytest
from fastapi.testclient import TestClient
from backend.app import app  # Import from backend.app.py

client = TestClient(app)

# Directory containing test CSV files
TEST_CSV_DIR = './test_files'

# Function to get a list of all CSV files in the test directory
def get_csv_files(directory):
    return [os.path.join(directory, file) for file in os.listdir(directory) if file.endswith('.csv')]

# Test for the /scanML/ endpoint
@pytest.mark.asyncio
@pytest.mark.parametrize("csv_file", get_csv_files(TEST_CSV_DIR))
async def test_scanML(csv_file):
    with open(csv_file, 'rb') as f:
        response = client.post("/scanML/", files={"file": ("test.csv", f, "text/csv")})
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    for item in data:
        assert 'id' in item
        assert 'file_name' in item
        assert 'pii_type' in item
        assert 'pii_value' in item

# Test for the /scanFile endpoint
@pytest.mark.asyncio
@pytest.mark.parametrize("csv_file", get_csv_files(TEST_CSV_DIR))
async def test_scanFile(csv_file):
    with open(csv_file, 'rb') as f:
        response = client.post("/scanFile", files={"file": ("test.csv", f, "text/csv")})
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    for item in data:
        assert 'id' in item
        assert 'file_name' in item
        assert 'pii_type' in item
        assert 'pii_value' in item

# Test for unsupported file format
@pytest.mark.asyncio
async def test_unsupported_file_type():
    # Test for PDF (unsupported in the current code)
    with open('./test_files/sample.pdf', 'rb') as f:
        response = client.post("/scanML/", files={"file": ("test.pdf", f, "application/pdf")})
    assert response.status_code == 400
    assert "Unsupported file type" in response.json()['detail']

# Test for empty file upload
@pytest.mark.asyncio
async def test_empty_file():
    with open('./test_files/empty.csv', 'rb') as f:
        response = client.post("/scanML/", files={"file": ("empty.csv", f, "text/csv")})
    assert response.status_code == 200
    assert response.json() == []  # Expect an empty list because no PII is found

# Test PII data insertion into MongoDB
@pytest.mark.asyncio
async def test_pii_data_insertion():
    with open('./test_files/sample.csv', 'rb') as f:
        response = client.post("/scanFile", files={"file": ("sample.csv", f, "text/csv")})
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    
    # Check if the inserted PII data is actually in MongoDB
    pii_record = data[0]  # Assuming at least one PII is found
    assert 'id' in pii_record
    assert 'file_name' in pii_record
    assert 'pii_type' in pii_record
    assert 'pii_value' in pii_record

    # Retrieve and check the inserted data in MongoDB
    db_record = await client.get(f"/retrieveAll")
    assert pii_record in db_record.json()

# Test PII deletion
@pytest.mark.asyncio
async def test_delete_pii():
    # Assuming PII data exists in the database
    data = {
        "file_name": "sample.csv",
        "pii_value": "123-45-6789"  # Example PII value
    }
    
    response = client.delete("/delete/", json=data)
    assert response.status_code == 200
    assert response.json()['detail'] == "Record deleted successfully."

# Test delete all PII data
@pytest.mark.asyncio
async def test_delete_all_pii():
    response = client.delete("/deleteAll")
    assert response.status_code == 200
    assert 'detail' in response.json()
