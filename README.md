# ParaBank Automation Project

## Overview
This project is a comprehensive automation framework designed for testing the ParaBank web application. The framework is built using Python and integrates tools such as Selenium, Pytest, and Allure to ensure robust end-to-end testing. The goal of this project is to automate key functionalities of the ParaBank application, provide detailed test reports, and integrate seamlessly into CI/CD pipelines for continuous testing and deployment.

## Project Structure
The project is organized into the following main directories and files:

```
ParaBankAutomation/
|-- .venv/                # Virtual environment folder
|-- driver_util.py        # Utility functions for WebDriver management
|-- tests/                # Test cases for different features
|   |-- test_login.py     # Test script for login functionality
|   |-- test_transfer.py  # Test script for fund transfer functionality
|-- requirements.txt      # Python dependencies
|-- README.md             # Project documentation
```

## Prerequisites
- Python 3.8 or higher
- Google Chrome installed
- ChromeDriver (compatible version with Chrome)
- Git for version control
- Allure for reporting

## Running Tests
To run the test scripts and generate Allure reports, follow these steps:

### Step 1: Run the Tests
Ensure the virtual environment is activated and execute:
```bash
pytest tests/ --alluredir=./allure-results
```
This will run all the test cases in the `tests/` directory and save the results in the `allure-results` folder.

### Step 2: Generate and Serve the Allure Report
Generate the report with the following command:
```bash
allure generate ./allure-results -o ./allure-report --clean
```
Serve the report in a web browser:
```bash
allure serve ./allure-results
```

## Project Highlights
- **Login Test**: Validates user authentication with valid and invalid credentials.
- **Fund Transfer Test**: Ensures the accuracy of the fund transfer process between accounts.
- **Modular Structure**: Utility functions like `get_driver()` are stored in `driver_util.py` for better code reusability.
- **Detailed Reporting**: Allure provides comprehensive test result visualization.

## Continuous Integration/Continuous Deployment (CI/CD)
The project can be integrated with GitLab CI/CD pipelines or AWS services for automated test execution as part of a larger DevOps process. This setup enables:
- Automated triggering of test runs on code push.

## Future Enhancements
- Adding more test coverage for other modules of ParaBank.
- Integrating parallel test execution with `pytest-xdist`.
- Setting up scheduled test runs using Jenkins or GitLab CI/CD.

