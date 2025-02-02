# !/bin/bash

host=localhost 
port=8741
if [ "$1" = "dev" ]; then
port="7741 --reload"
fi

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
python_executable=$(which python3.11)
cd $SCRIPTPATH
echo "Starting backend on $host:$port with $python_executable" 
$python_executable -m venv $SCRIPTPATH/.venv
source $SCRIPTPATH/.venv/bin/activate
$python_executable -m pip install --upgrade pip
$python_executable -m pip install uv
$python_executable -m uv pip install -r requirements.txt
$python_executable -m uvicorn core.app:app --host $host --port $port