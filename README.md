# iOS SDK Analyser

This python program allows you to analyse iOS apps to find evidence of third-party libraries.
The program is divided into two analytical methods: Static - The identification of known SDKs used by an app , and Dynamic - The identification of domains used by an app.


## Requirements

Before you begin, ensure you have the following dependencies:

- **Operating System**: MacOS or Linux
- **Device**: Jailbroken iPhone
- **Apple ID**: It is recommended to set up a spare Apple ID for this project to avoid any potential issues with your primary account.
- **Cable**: USB-A to Lightning cable (USB-C to lightning can be unstable)

## Installation

To install and set up the project, follow these steps:

1. **Clone the repository**:
    ```sh
    git clone --recursive https://github.com/yourusername/iOS_SDK_ANALYSER.git
    cd iOS_SDK_ANALYSER
    ```

2. **Set up a virtual environment**:
    ```sh
    python3 -m venv venv
    source venv/bin/activate
    ```

3. **Install dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

4. **Set up Frida and libimobiletools**:
    - Follow the official [Frida installation guide](https://frida.re/docs/installation/).
    - Follow the official [libimobiletools installation guide](https://libimobiledevice.org/).

5. **Connect your jailbroken iPhone**:
    - Ensure your iPhone is connected to your computer using the USB-A to Lightning cable.
    - Verify that your iPhone is detected by running:
    ```sh
    idevice_id -l
    ```

6. **Configure your Apple ID**:
    - Use the spare Apple ID to sign in on your jailbroken iPhone.
    - Ensure that the Apple ID is properly configured to avoid any interruptions during the analysis process.

## Using the program


### Static analysis
![iOS SDK Analyser](https://policyreview.info/sites/default/files/assets/images/node-1763/2.png)


## Project Status

- [x] Initial project setup
- [ ] Implement central CLI
- [ ] Write a utility script (App downloads, Search, etc.)
- [ ] Create frida API and expose to python
- [ ] Add verbose options
- [ ] Improve documentation for Frida
- [ ] Implement jailbreak detection script
- [ ] Documentation for jailbreak
- [ ] Documentation for ipatool

## License

This repository is licensed under Creative Commons Attribution 4.0 International CC BY 4.0.
This project and its works are funded by the ERC research project, Datafied Living at The University of Copenhagen.

## 
