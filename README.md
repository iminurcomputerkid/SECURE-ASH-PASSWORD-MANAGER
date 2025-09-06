__________________SECURE ASF PASSWORD MANAGER 🔐__________________

(CURRENTLY BETA)

A Python-based password manager that encrypts credentials and securely stores them in a Turso DB.

__________________Key Features__________________

Encryption: Uses Argon2 and a Fernet cipher to securely encrypt credentials + randomly generates unique salt phrase for each user.

Easy Installation: Install dependencies with simple commands.

Flexible Execution: Run via VSCode, terminal batch execution, or other IDEs.

__________________Installation and Run Instructions__________________

Clone the repository using gitbash:

git clone https://github.com/iminurcomputerkid/SECURE-ASF-PASSW-MAN.git

Open in IDE of choice (or nano if you're sligtly insane)

If nano or vim:
pip install -r requirements.yml
python3 main.py

If IDE:
Make new virtual environment and install the dependencies in requirements.yml 

For VsCode: (Ctrl+Shift+P), scroll down until you see select python interpreter, Create Environment, Use whatever python installation you want, click requirements when it asks if you'd like to add any dependencies and create it, wait a few minutes for everything to install and your virtual env to activate 

Then run :D
  

__________________Batch Execution Setup (OPTIONAL):__________________

a. Create a batch file:

In your repo folder, create a file named 'run_pwman.bat' with the following content:

@echo off
REM SECURE ASF PASSW MAN Batch Execution
python script3.py
pause

b. Move the batch file to a directory in your PATH (e.g., C:\Users\YourUsername\bin):

mv run_pwman.bat C:\Users\YourUsername\bin

c. (If needed) Set execute permissions on Unix-like systems:

chmod +x /path/to/your/bin/run_pwman.bat

d. Run the program:

For PowerShell/WSL: ./run_pwman.bat
For CMD: run_pwman.bat

