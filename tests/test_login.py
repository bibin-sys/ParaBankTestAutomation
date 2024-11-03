import pytest
import allure
from driver_util import get_driver
from pages.login_page import LoginPage

@allure.feature("Login Feature")
@allure.story("User logs in successfully")
def test_login_to_parabank():
    driver = get_driver()
    login_page = LoginPage(driver)
    try:
        with allure.step("Open ParaBank login page"):
            driver.get("https://parabank.parasoft.com/parabank/index.htm")
        
        with allure.step("Enter login credentials and submit"):
            login_page.login("bibinbiju", "1234")

        with allure.step("Verify login success"):
            assert login_page.is_login_successful(), "Login failed - Accounts Overview page not found"
            allure.attach(driver.get_screenshot_as_png(), name="LoginSuccess", attachment_type=allure.attachment_type.PNG)
    finally:
        driver.quit()
if __name__ == "__main__":
    test_login_to_parabank()