# !/bin/bash

host=localhost
port=7741
source .venv/bin/activate
python_executable=$(which python3.11)
echo "Starting wao.moe backend on $host:$port with $python_executable" 
$python_executable -m venv .venv
$python_executable -m pip install --upgrade pip
$python_executable -m pip install -r requirements.txt
$python_executable -m uvicorn app:app --host $host --port $port --reload --log_