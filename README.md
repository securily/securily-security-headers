# Security Headers Scanner by Securily
![Security Headers Scanner by Securily](securily-security-headers.png)

This tool has been developed by Securily to help developers troubleshoot and analyze the security headers in their web applications. By checking the presence and configuration of security headers, this scanner aims to prevent potential security vulnerabilities and protect web applications from being compromised.

## Features

- **Header Analysis**: The tool reads and analyzes common security headers, including Strict-Transport-Security and Content-Security-Policy, to assess their configuration.
- **OpenAI Integration**: Utilizes the OpenAI API to provide intelligent prompts for configuring security headers.
- **Configuration Management**: Allows users to configure and customize the severity rating, reasoning, remediation steps, and possible values for each security header.
- **Verbose Output**: Provides detailed information and feedback during the scanning process for better understanding and troubleshooting.
- **Configuration Persistence**: Stores the header configuration in a JSON file for easy reloading and persistence across multiple runs.
- **Results Reporting**: Generates a JSON report of the header analysis results, including header status, severity, reasoning, and remediation steps.

## Quickstart
```shell
   git clone https://github.com/securily/security-headers-scanner.git
   ./securily-headers.sh -o <OPENAI_API_KEY> -u https://securily.com
```

## Usage

1. Clone the repository: `git clone https://github.com/securily/security-headers-scanner.git`
2. Install the required dependencies: `pip install -r requirements.txt`
3. Obtain an API key from OpenAI by following these steps:
   - Visit the OpenAI website: [https://openai.com](https://openai.com)
   - Click on the "Get started" or "Sign up" button to create an account.
   - Complete the registration process by providing the required information and agreeing to the terms of service.
   - Once you have created an account and logged in, navigate to the OpenAI API section or dashboard.
   - Follow the instructions provided to generate an API key for accessing the OpenAI API services.
   - Copy the generated API key and securely store it.
4. Run the scanner: `python security_headers_scanner.py -v -o <OPENAI_API_KEY>`

Replace `<OPENAI_API_KEY>` with your actual OpenAI API key.

Make sure to keep your API key confidential and avoid sharing it publicly or committing it to version control systems. It is recommended to store the API key in a secure environment, such as an environment variable or a separate configuration file.

## Contributing

Contributions are welcome! If you encounter any issues or have suggestions for improvements, please feel free to submit a pull request or open an issue in the GitHub repository.

## License

This tool is open source and licensed under the [GNU General Public License v3.0](LICENSE).
