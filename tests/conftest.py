import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pytest
import uuid
from app import create_app

@pytest.fixture
def tmp_path(request):
    path=Path(__file__).resolve().parents[1]/".pytest_tmp"/(request.node.name+"-"+uuid.uuid4().hex[:8])
    path.mkdir(parents=True,exist_ok=True)
    return path

@pytest.fixture
def app(tmp_path):
    return create_app({"TESTING":True,"DATABASE":str(tmp_path/"test.sqlite"),"SECRET_KEY":"test"})
@pytest.fixture
def client(app):return app.test_client()
