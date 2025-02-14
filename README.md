__________________SECURE ASF PASSWORD MANAGER 🔐__________________

(CURRENTLY BETA, REACH OUT TO ME FOR AUTHENTICATION TOKEN TO ACCESS RESTRICTED DB: https://www.linkedin.com/in/julien-niles-83926a308/)

A Python-based password manager that encrypts credentials and securely stores them in a Turso DB.

__________________Key Features__________________

Encryption: Uses Argon2, PBKDF2, and a Fernet cipher to securely encrypt credentials + randomly generates unique salt phrase for each user.

Easy Installation: Install dependencies with simple commands.

Flexible Execution: Run via VSCode, terminal batch execution, or other IDEs.

__________________Installation__________________

Clone the repository:

git clone https://github.com/iminurcomputerkid/SECURE-ASF-PASSW-MAN.git
cd SECURE-ASF-PASSW-MAN

Install Dependencies:

pip install -r requirements.yml

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

