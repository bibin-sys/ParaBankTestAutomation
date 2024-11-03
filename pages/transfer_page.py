'''
Created on 02-Nov-2024

@author: bibin
'''
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
from .base_page import BasePage

class TransferPage(BasePage):
    TRANSFER_LINK = (By.LINK_TEXT, "Transfer Funds")
    AMOUNT_FIELD = (By.ID, "amount")
    FROM_ACCOUNT_SELECT = (By.ID, "fromAccountId")
    TO_ACCOUNT_SELECT = (By.ID, "toAccountId")
    TRANSFER_BUTTON = (By.XPATH, "//input[@value='Transfer']")
    SUCCESS_MESSAGE = (By.XPATH, "//h1[normalize-space()='Transfer Complete!']")

    def navigate_to_transfer_page(self):
        self.click_element(self.TRANSFER_LINK)

    def transfer_funds(self, amount, from_account_value, to_account_value):
        self.input_text(self.AMOUNT_FIELD, amount)
        Select(self.find_element(self.FROM_ACCOUNT_SELECT)).select_by_value(from_account_value)
        Select(self.find_element(self.TO_ACCOUNT_SELECT)).select_by_value(to_account_value)
        self.click_element(self.TRANSFER_BUTTON)

    def is_transfer_successful(self):
        try:
            return self.find_element(self.SUCCESS_MESSAGE).is_displayed()
        except:
            return False
