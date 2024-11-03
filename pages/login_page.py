'''
Created on 02-Nov-2024

@author: bibin
'''
from selenium.webdriver.common.by import By
from .base_page import BasePage

class LoginPage(BasePage):
    USERNAME_FIELD = (By.NAME, "username")
    PASSWORD_FIELD = (By.NAME, "password")
    LOGIN_BUTTON = (By.XPATH, "//input[@value='Log In']")
    ACCOUNT_OVERVIEW = "Accounts Overview"  # Used to check if the login was successful

    def login(self, username, password):
        self.input_text(self.USERNAME_FIELD, username)
        self.input_text(self.PASSWORD_FIELD, password)
        self.click_element(self.LOGIN_BUTTON)

    def is_login_successful(self):
        return self.ACCOUNT_OVERVIEW in self.driver.page_source
