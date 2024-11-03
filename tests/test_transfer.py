
import allure
from driver_util import get_driver
from pages.login_page import LoginPage
from pages.transfer_page import TransferPage

@allure.feature("Transfer Feature")
@allure.story("User transfers funds successfully")
def test_transfer_funds():
    driver = get_driver()
    login_page = LoginPage(driver)
    transfer_page = TransferPage(driver)

    try:
        with allure.step("Open ParaBank login page and log in"):
            driver.get("https://parabank.parasoft.com/parabank/index.htm")
            login_page.login("bibinbiju", "1234")
            assert login_page.is_login_successful(), "Login failed - Accounts Overview page not found"

        with allure.step("Navigate to Transfer Funds page and perform transfer"):
            transfer_page.navigate_to_transfer_page()
            transfer_page.transfer_funds("100", "13899", "13899")

        with allure.step("Verify transfer success"):
            assert transfer_page.is_transfer_successful(), "Fund transfer failed"
            allure.attach(driver.get_screenshot_as_png(), name="TransferSuccess", attachment_type=allure.attachment_type.PNG)
    finally:
        driver.quit()
if __name__ == "__main__":
    test_transfer_funds() 
