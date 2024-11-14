# Vuln_Search
Nmap scans hosts and queries searchsploit for any public exploits

# Use a Python Virtual Environment to run this

Create the venv environment

$ python -m venv <directory>

$ python3 -m venv venv

Activate it:

On Linux and MacOS, we activate our virtual environment with the source command. If you created your venv in 
the myvenv directory, the command would be:

$ source venv/bin/activate


Run the requirements scripts or whatever 

$ pip install -r ./requirements.txt


# Running the program
Single host:

python vuln_search.py -i [ip address]


Subnet searches

python vuln_search.py -i [subnet to scan]


Scan hosts from a file

python vuln_search.py -f [path to file]
