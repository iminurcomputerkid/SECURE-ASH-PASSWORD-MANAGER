# SECURE ASF PASSW MAN 🔐  🔒
A **Python-based password manager** that encrypts credentials and securely stores them in a **Turso database**.

---

## Features
- 🔒 **Encryption**: Securely encrypts stored credentials with Argon2, PBKDF2 and Fernet cipher.
- 🛠 **Easy Installation**: Install dependencies with simple commands.
- 💻 **Multiple Run Methods**: Works in VSCode or via terminal batch execution (Intended Use, likely can be used in other IDEs).

---

## 📥 Installation
### 1️⃣ Clone the Repo  
```bash
git clone https://github.com/YOUR-USERNAME/SECURE-ASF-PASSW-MAN.git
cd SECURE-ASF-PASSW-MAN

COMMAND TO INSTALL DEPENDENCIES: pip install -r requirements.yml

###2️⃣ (Optional: Batch Implementation)
Step 0.5. Change the directory to your repo folder (cd path\to\SECURE-ASF-PASSW-MAN)
Step 1. Create a .txt file within the repo folder, paste the text below, and save. 
bat
@echo off
REM SECURE ASF PASSW MAN Batch Execution
python script3.py
pause
Step 2. Open the terminal and move the batch file to your bin folder (or any folder in your PATH environment)
bash
mv SECURE-ASF-PASSW-MAN/run_pwman.bat C:\Users\YourUsername\bin
Step 3. Redirect to the home directory and execute batch file **ensure batch has execute permissions; execute the following if not)
bash
chmod +x C:\Users\YourUsername\bin
Then run the program
./run_pwman.bat in PowerShell (Terminal) and WSL (Linux and Windows subsystems for Linux) and run_pwman.bat (CMD)






