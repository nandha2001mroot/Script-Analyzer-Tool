# Script-Analyzer-Tool
A Python tool for analyzing PowerShell (.ps1) and Python (.py) scripts. It identifies functionality, flags suspicious behaviors (like file deletion or network calls), assesses risk (Low/Medium/High), and generates detailed reports for technical and non-technical users.
# Script Analyzer Tool

A Python-based tool designed to analyze both PowerShell (.ps1) and Python (.py) scripts. It provides detailed reports on script functionality, potential risks, and generates summaries for both technical and non-technical users.

## Features

*   **Dual-Language Support:** Analyzes both `.ps1` and `.py` files.
*   **Functionality Analysis:** Describes what the script is designed to do.
*   **Execution Summary:** Explains potential actions in plain language.
*   **Command Detection:** Lists major functions, modules, and system commands used.
*   **Suspicious Behavior Flagging:** Detects potentially risky actions (e.g., file deletion, network requests, code execution).
*   **Risk Rating:** Provides a Low, Medium, or High risk assessment.
*   **Technical Notes:** Explains the significance of flagged items.
*   **Non-Technical Summary:** Offers a simple description for general users.
*   **Structured Output:** Generates a clear, readable report saved as a `.txt` file.

## Author

For more information about the author, visit: [Nandha Kumar M](https://www.linkedin.com/in/nandha-kumar-m-952342159/)

## Requirements

*   Python 3.x installed on your system.

## How to Use

1.  **Clone or Download:** Get the `script_analyzer.py` file from this repository.
2.  **Open Terminal/Command Prompt:** Navigate to the directory containing the `script_analyzer.py` file.
3.  **Run the Script:** Execute the following command, replacing `path/to/your/script.ps1` or `path/to/your/script.py` with the actual path to the script you want to analyze.

    ```bash
    python script_analyzer.py path/to/your/script.ps1
    # Or
    python script_analyzer.py path/to/your/script.py
    ```

4.  **Check the Output:** The analysis report will be automatically generated and saved to:
    `C:\Users\my pc\Downloads\script_analysis_report.txt`

    **Example Command:**
    ```bash
    python script_analyzer.py C:\Scripts\example_script.ps1
    ```

    **Expected Output:**
    After running the command, you will see a message like:
    ```
    Analysis complete. Report saved to: C:\Users\my pc\Downloads\script_analysis_report.txt
    ```
    The `script_analysis_report.txt` file will contain the full analysis report in the following format:

    ```
    SCRIPT ANALYSIS REPORT
    ====================

    File: C:\Scripts\example_script.ps1
    Type: PowerShell
    Analysis Time: 2023-10-27 12:00:00
    Lines of Code: 15

    SCOPE & FUNCTIONALITY
    ---------------------
    System monitoring and management script - likely checks system processes or services.

    EXECUTION SUMMARY
    -----------------
    If executed, this script will: Downloads files or sends requests to remote servers.

    DETECTED FUNCTIONS/COMMANDS
    ---------------------------
    Get-Process, Get-Service, Invoke-WebRequest, Write-Host

    SUSPICIOUS BEHAVIOR
    -------------------
    Invoke-WebRequest

    RISK RATING: MEDIUM

    TECHNICAL NOTES
    ---------------
    - Invoke-WebRequest: Used for network requests. Could download malicious content or send sensitive data.

    NON-TECHNICAL SUMMARY
    ---------------------
    This PowerShell script connects to the internet, which means it can download files or send information online. Be cautious if you don't trust the source.

    ANALYSIS COMPLETE
    ```

## Important Notes

*   This tool performs static analysis (reading the script code) and does NOT execute the script being analyzed, making it safer to use.
*   The risk assessment is based on pattern matching and common potentially dangerous commands. It is not foolproof and should be used as a first step in evaluating a script's safety.
*   Ensure you have permission to analyze the target script file.

## License

[Choose a license, e.g., MIT License, Apache 2.0, etc. If you don't specify one, it defaults to All Rights Reserved by GitHub's terms. Consider adding a `LICENSE` file.]
