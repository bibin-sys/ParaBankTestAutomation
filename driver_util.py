import chromedriver_autoinstaller
from selenium import webdriver

def get_driver():
    """Installs the appropriate chromedriver and returns an initialized WebDriver instance."""
    chromedriver_autoinstaller.install()  # Automatically installs chromedriver if not present
    driver = webdriver.Chrome()
    driver.maximize_window()  # Optional: maximize the window for better visibility
    return driver
