## The Problem

- **The Old Code:** The unicorn software package contains an old configuration file. This file contains an instruction that tells the compiler: "I require CMake version 2.8 to be built."

- **The New Compiler:** Modern Mac computers use a highly updated version of the CMake compiler. The developers of CMake recently updated their software to strictly reject any configuration files that request a version older than 3.5.

- **The Crash:** When Unicorn attempts to install, the new Mac compiler reads the request for version 2.8, outputs a fatal error, and stops the process.

- **The Missing Feature:** There is a known command-line flag (-DCMAKE_POLICY_VERSION_MINIMUM=3.5) that forces the new compiler to ignore the version rule and compile the code anyway. However, the Unicorn installation script (setup.py) is hardcoded to run the cmake command by itself. It does not provide any way for the user to pass custom flags into the command.

### The Solution: The Man-in-the-Middle Attack 

Since we could not modify Unicorn's hardcoded script, and we could not downgrade the Mac's compiler, we intercepted the communication between the two.

1. **Path Prioritization:** When a program executes a command like cmake, the operating system does not know exactly where that program is located. Instead, it searches through a specific list of directories (called the PATH variable) from top to bottom. Because a Python virtual environment was active, the very first directory the operating system checked was the virtual environment's bin directory (hexstrike-env/bin/).

2. **Creating the Interceptor:** We created a standard text file inside hexstrike-env/bin/ and named it exactly cmake. We then changed the file permissions to make it an executable program.

3. **The Interception:** When the Unicorn installation script executed the cmake command, the operating system found our executable file first and ran it. Unicorn was completely unaware that it was not communicating with the actual Mac compiler.

4. **Modifying the Instructions:** Inside our custom cmake file, we wrote a short script. The script was programmed to take the exact instructions Unicorn sent, append the required bypass flag (-DCMAKE_POLICY_VERSION_MINIMUM=3.5) to the end of those instructions, and then forward the modified command directly to the absolute file path of the real Mac compiler (/opt/homebrew/bin/cmake).

5. **Successful Execution:** The real Mac compiler received the modified instructions. Because the bypass flag was present, it ignored the version error and successfully compiled the Unicorn software.Old Code: The unicorn software package contains an old configuration file. This file contains an instruction that tells the compiler: "I require CMake version 2.8 to be built."



### Prerequisites
Ensure you have Homebrew and pyenv installed on your Mac.
* `brew install cmake`
* `pyenv install 3.11.9`

### Step-by-Step Installation

#### Step 1: Clone the Repository
Open your terminal and clone the tool:
```bash
git clone [https://github.com/0x4m4/hexstrike-ai.git](https://github.com/0x4m4/hexstrike-ai.git)
cd hexstrike-ai
```

### Step 2: Set the Local Python Version
Force the folder to use the stable 3.11.9 foundation:

```bash
pyenv local 3.11.9
```

### Step 3: Create and Activate the Virtual Environment

```bash 
python -m venv hexstrike-env
source hexstrike-env/bin/activate
```

### Step 4: Install Base Build Tools

```bash
pip install setuptools wheel
```

#### Step 5: Create the Compiler Wrapper (The Magic Fix)
Copy and paste this entire block into your terminal and press Enter. This creates a script that intercepts the compiler and injects the necessary bypass codes.

```bash
cat << 'EOF' > hexstrike-env/bin/cmake
#!/bin/bash
if [[ "$*" == *"--build"* ]]; then
  /opt/homebrew/bin/cmake "$@"
else
  /opt/homebrew/bin/cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 "$@"
fi
EOF
```


#### Step 6: Make the Wrapper Executable
```bash
chmod +x hexstrike-env/bin/cmake
```


#### Step 7: Install the Stubborn Package First
Force unicorn to install using our modified environment and does not allow the pip to create it's own enviroment 

```bash
pip install unicorn==2.0.1.post1 --no-build-isolation
```

#### Step 8: Install the Remaining Toolkit
Once Unicorn installs successfully, the rest of the tools will install without issue:

```Bash
pip install -r requirements.txt
```