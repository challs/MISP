
# Pytest based tests for MISP UI

# you need to install these python packages:
#  pytest pytest-selenium
#
# Export the following environment variables:
#  MISP_ADMIN_EMAIL         - valid username
#  MISP_ADMIN_PASSPHRASE    - password for the user
#  LINOTP_OTP               - valid OTP value. You can use the 'pw' token in challenge-response mode
#
# Pass the following parameters to pytest:
#
#  --driver <selenium-driver-type>
#  --base-url <misp-base-url>
#  --sensitive-url=NONE
#
# Example test run:
#
# MISP_ADMIN_EMAIL=admin@example.com MISP_ADMIN_PASSPHRASE='TestPassword123!' LINOTP_OTP='111111' \
#  pytest --driver chrome --base-url http://localhost:3080 --sensitive-url=NONE

import os
import pytest

from typing import Dict

@pytest.fixture
def config(base_url):

    base = os.getenv('MISP_BASEURL') or base_url
    base = base.strip('/')

    # Configuration
    config = dict(
        email=os.getenv('MISP_ADMIN_EMAIL'),
        password=os.getenv('MISP_ADMIN_PASSPHRASE'),
        otp=os.getenv('LINOTP_OTP'),
        baseurl=base,
        pluginurl=base + '/lin_o_t_p_auth'
    )
    return config

def get_notification_text(selenium):
    """
    Return the text in the flash area
    """
    return selenium.find_elements_by_xpath("//div[@id='flashContainer']/*")[0].text

def parse_login_page(selenium, config) -> Dict:
    elements = {
        'email': selenium.find_element_by_id('LinOTPUserPasswordEmail'),
        'password': selenium.find_element_by_id('LinOTPUserPasswordPassword'),
        'loginButton': selenium.find_element_by_css_selector('#LinOTPUserPasswordIndexForm button[type="submit"]'),
        'selfServiceLink': selenium.find_element_by_link_text("LinOTP Selfservice"),
        'notificationText': get_notification_text(selenium),
    }

    return elements

def parse_otp_page(selenium, config) -> Dict:
    elements = {
        'otp': selenium.find_element_by_id('LinOTPOTPOTP'),
        'loginButton': selenium.find_element_by_css_selector('#LinOTPOTPIndexForm button[type="submit"]'),
        'notificationText': get_notification_text(selenium),
    }

    return elements

@pytest.fixture
def login_page(selenium: 'selenium.webdriver', config) -> Dict:
    """
    Visit the login page and return an array pointing to the elements of the page
    """
    selenium.get(config['pluginurl'] + 'Login')
    assert selenium.find_element_by_link_text("LinOTP Selfservice")

    return parse_login_page(selenium, config)

def test_linotp_redirect(selenium: 'selenium.webdriver', config: Dict):
    selenium.get(config['baseurl'])
    assert selenium.current_url == config['pluginurl'] + '/Login'

def test_login_page_contents(login_page: Dict):

    assert login_page['notificationText'] == ''

    # The page should have a link to the selfservice page
    assert login_page['selfServiceLink']

def test_empty_credentials_notification(selenium, login_page: Dict):

    login_page['loginButton'].click()
    login_page = parse_login_page(selenium, config)
    msg='Invalid credentials. Please check that you have entered the correct '\
        'username and password, and that you have a valid second factor enrolled.'

    assert msg in login_page['notificationText']
    
    # The page should have a link to the selfservice page
    assert login_page['selfServiceLink']

def do_login(login_page, selenium, config):
    """
    Enter valid user and password on login page
    """
    login_page['email'].send_keys(config['email'])
    login_page['password'].send_keys(config['password'])
    login_page['loginButton'].click()

@pytest.fixture
def otp_page(login_page, selenium: 'selenium.webdriver', config) -> Dict:
    """
    Go to the OTP page and return an array pointing to the elements of the page
    """
    do_login(login_page, selenium, config)

    return parse_otp_page(selenium, config)

def do_otp(otp_page, selenium, config):
    """
    Enter OTP on page and submit
    """
    otp_page['otp'].send_keys(config['otp'])
    otp_page['loginButton'].click()

def test_linotp_login(otp_page, selenium, config):
    do_otp(otp_page, selenium, config)
    assert selenium.current_url == config['baseurl'] + '/'
