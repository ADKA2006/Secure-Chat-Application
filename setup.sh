#!/bin/zsh
echo "Setting up Secure Chat App"


python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
echo "Now do the following"
echo " "
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Run the server: python server.py"
echo "3. Open browser @: http://localhost:5000"
