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
#  MISP_USER_EMAIL=user@example.com MISP_USER_PASS='secret' MISP_USER_OTP='111111' \
#  LINOTP_BASEURL=https://linotpsvc.example.com LINOTP_USER=admin LINOTP_PASS=secret \
#  pytest --driver chrome --base-url http://localhost:3080 --sensitive-url=NONE
# export MISP_KEY=$(mysql -Ns -h `docker-get-ip misp_db` -u misp -pmisp misp -e "select authkey from users where id=1;")

import os
import pytest

from typing import Callable, Dict, Generator
from selenium import webdriver
from linotpcli import LinOTPCli
from linotpcli.policy import Policy, Action, PolicyFilter
from linotpcli.policy.authentication import OTPPin, ChallengeResponse

from pymisp import ExpandedPyMISP as PyMISP, MISPUser
from selenium.webdriver.common.action_chains import ActionChains


@pytest.fixture(scope="module")
def misp_base_url(base_url: str) -> str:
    base = os.getenv("MISP_BASEURL") or base_url
    base = base.strip("/")
    return base


@pytest.fixture(scope="module")
def config(misp_base_url) -> Dict:
    # Configuration
    config = dict(
        email=os.getenv("MISP_ADMIN_EMAIL"),
        password=os.getenv("MISP_ADMIN_PASSPHRASE"),
        authkey=os.getenv("MISP_KEY"),
        otp=os.getenv("LINOTP_OTP"),
        pluginurl=misp_base_url + "/lin_o_t_p_auth",
        useremail=os.getenv("MISP_USER_EMAIL"),
        userpass=os.getenv("MISP_USER_PASS"),
        userotp=os.getenv("MISP_USER_OTP"),
        linotp_url=os.getenv("LINOTP_BASEURL"),
        linotp_user=os.getenv("LINOTP_USER", "admin"),
        linotp_password=os.getenv("LINOTP_PASS", "admin"),
        linotp_realm=os.getenv("LINOTP_REALM", "misp"),
    )
    return config


@pytest.fixture(scope="module")
def misp(misp_base_url, config) -> PyMISP:
    url = misp_base_url
    key = config["authkey"]
    misp = PyMISP(url, key, True, "json")
    misp.toggle_global_pythonify()
    return misp


@pytest.fixture(scope="module")
def linotpcli(config) -> LinOTPCli:
    """
    LinOTP API client fixture
    """
    apiclient = LinOTPCli(
        config["linotp_url"], config["linotp_user"], config["linotp_password"]
    )
    return apiclient


@pytest.fixture(scope="module")
def misp_user_factory(misp: PyMISP) -> MISPUser:
    def make_misp_user(email: str, password: str, change_pw_flag=0):
        """
        Return a MISP user instance

        The user is a pymisp object
        """
        existing_users = [u for u in misp.users() if u.email == email]
        if existing_users:
            misp.delete_user(existing_users[0])
        user = MISPUser()
        user.from_dict(
            email=email,
            role_id=1,
            org_id=1,
            password=password,
            disabled=0,
            change_pw=change_pw_flag,
            termsaccepted=1,
        )
        user = misp.add_user(user, pythonify=True)
        assert "errors" not in user, user["errors"]
        return user

    return make_misp_user


@pytest.fixture
def user(
    config, misp: PyMISP, misp_user_factory, linotpcli: LinOTPCli
) -> Generator[Callable, None, None]:
    """
    Factory fixture for a user configured for testing

    The returned fixture function creates a new user in MISP
    via the PyMISP API and assigns a token in LinOTP via the API.
    If `challenge_response` is enabled, the token will be in
    challenge response mode, requiring a separate OTP. If
    `password_reset` is enabled, the MISP user's reset password
    will be set, requiring a password change immediately after
    login.

    The created users, policies and tokens will be deleted during teardown.

    The function returns a dict containing information about the user:
      * email
      * password
      * otp
    """

    # Keep a record of users so we can remove them afterwards
    created_users = []
    created_policies = []
    created_tokens = []

    def _user(
        email: str,
        password: str,
        otp: str,
        pin_policy,
        challenge_response: bool,
        password_reset: bool,
    ):
        # Create the user in MISP
        user = misp_user_factory(email, password, password_reset & 1 | 0)
        created_users.append(user)

        # Create policies for the users token
        filter = PolicyFilter(user=email)
        action = OTPPin(pin_policy)
        actions = [action]
        if challenge_response:
            # Create challenge response action for the users' token
            actions.append(ChallengeResponse("pw"))
        policy = Policy(
            "otp_pin_test", scope=action.scope, actions=actions, filter=filter
        )
        linotpcli.add_policy(policy)
        created_policies.append(policy)

        token = linotpcli.enroll_password_token(
            password=otp, user=email, realm=config["linotp_realm"]
        )
        created_tokens.append(token)

        return dict(
            email=email, password=password, otp=otp, misp_user=user, token=token,
        )

    yield _user

    # Clean up created items
    for user in created_users:
        misp.delete_user(user)
    for policy in created_policies:
        linotpcli.delete_policy(policy)
    for token in created_tokens:
        linotpcli.delete_token(token["serial"])


@pytest.fixture
def user_with_challenge_response(user) -> Dict:
    """
    Challenge response user

    Creates a valid user in MISP and assigns a token for
    challenge response authentication
    """
    return user(
        email="user_with_challenge_response@example.com",
        password="SeleniumPass1!",
        otp="111222",
        pin_policy=OTPPin.PASSWORD_AND_OTP,
        challenge_response=True,
        password_reset=False,
    )


@pytest.fixture
def user_with_challenge_response_and_password_reset(user) -> Dict:
    """
    Challenge response user with password reset flag
    """
    return user(
        email="user_with_challenge_response_password_reset@example.com",
        password="SeleniumPass2!",
        otp="111333",
        pin_policy=OTPPin.PASSWORD_AND_OTP,
        challenge_response=True,
        password_reset=True,
    )


@pytest.fixture
def user_with_one_stage_login(user) -> Dict:
    """
    User who has a simple login sequence without challenge response

    Creates a valid user in MISP and assigns a token for
    simple authentication. The OTP login form will not be used.
    """
    return user(
        email="user_with_one_stage_login@example.com",
        password="SeleniumPass2!",
        otp="222333",
        pin_policy=OTPPin.PASSWORD_AND_OTP,
        challenge_response=False,
        password_reset=False,
    )


def get_notification_text(selenium):
    """
    Return the text in the flash area
    """
    return selenium.find_elements_by_xpath("//div[@id='flashContainer']/*")[0].text


def parse_login_page(selenium: webdriver) -> Dict:
    """
    Find all the elements we expect to see in the LinOTP plugin login page

    @returns a dictionary of elements plus the notification bar text
    """
    elements = {
        "email": selenium.find_element_by_id("LinOTPUserPasswordEmail"),
        "password": selenium.find_element_by_id("LinOTPUserPasswordPassword"),
        "loginButton": selenium.find_element_by_css_selector(
            '#LinOTPUserPasswordIndexForm button[type="submit"]'
        ),
        "selfServiceLink": selenium.find_element_by_link_text("LinOTP Selfservice"),
        "notificationText": get_notification_text(selenium),
    }

    return elements


def parse_otp_page(selenium: webdriver) -> Dict:
    """
    Find all the elements we expect to see in the LinOTP plugin OTP page

    @returns a dictionary of elements plus the notification bar text
    """
    elements = {
        "otp": selenium.find_element_by_id("LinOTPOTPOTP"),
        "loginButton": selenium.find_element_by_css_selector(
            '#LinOTPOTPIndexForm button[type="submit"]'
        ),
        "notificationText": get_notification_text(selenium),
    }

    return elements


def do_change_password_page(
    selenium: webdriver, misp_base_url, new_password: str
) -> None:
    """
    Change the users password

    Prerequesite: We are logged in and on the change password page
    """

    assert selenium.current_url == misp_base_url + "/users/change_pw"
    page = dict(
        password_box=selenium.find_element_by_css_selector("input#UserPassword"),
        confirm_password_box=selenium.find_element_by_css_selector(
            "input#UserConfirmPassword"
        ),
        submit_button=selenium.find_element_by_css_selector(
            "#UserChangePwForm > button"
        ),
    )

    page["password_box"].send_keys(new_password)
    page["confirm_password_box"].send_keys(new_password)
    page["submit_button"].click()


@pytest.fixture
def login_page(selenium: webdriver, config):
    """
    Factory fixture function: visit login page

    Vsits the login page and return an array pointing to the elements of the page
    """

    def _login_page() -> Dict:
        selenium.get(config["pluginurl"] + "Login")
        assert selenium.find_element_by_link_text("LinOTP Selfservice")

        return parse_login_page(selenium)

    return _login_page


@pytest.fixture
def do_login(login_page):
    """
    Factory fixture function: Enter username + password on login page

    Enter valid user and password on login page
    """

    def _do_login(email: str, password: str):
        login = login_page()
        login["email"].send_keys(email)
        login["password"].send_keys(password)
        login["loginButton"].click()

    return _do_login


def do_otp(otp_page, selenium: webdriver, otp):
    """
    Enter OTP on page and submit
    """
    otp_page["otp"].send_keys(otp)
    otp_page["loginButton"].click()


@pytest.fixture
def otp_page(do_login, selenium: webdriver, user_with_challenge_response: Dict) -> Dict:
    """
    Go to the OTP page and return an array pointing to the elements of the page
    """
    do_login(
        user_with_challenge_response["email"], user_with_challenge_response["password"]
    )

    return parse_otp_page(selenium)


def test_linotp_redirect(selenium: webdriver, misp_base_url: str, config: Dict):
    """Check we are redirected to the plugin URL"""
    selenium.get(misp_base_url)
    assert selenium.current_url == config["pluginurl"] + "/Login"


def test_login_page_contents(login_page):
    """Check the contents of the login page"""

    elements = login_page()
    assert elements["notificationText"] == ""

    # The page should have a link to the selfservice page
    assert elements["selfServiceLink"]


def test_empty_credentials_notification(selenium: webdriver, login_page):

    login_page()["loginButton"].click()
    login_elements = parse_login_page(selenium)
    msg = (
        "Invalid credentials. Please check that you have entered the correct "
        "username and password, and that you have a valid second factor enrolled."
    )

    assert msg in login_elements["notificationText"]

    # The page should have a link to the selfservice page
    assert login_elements["selfServiceLink"]


@pytest.fixture
def check_for_login_success(selenium: webdriver, misp_base_url: str):
    """
    Returns a function to assert that we have just logged in successfully
    """

    def _check_for_login_success(expected_url: str = "/") -> None:
        assert selenium.current_url == misp_base_url + expected_url

    return _check_for_login_success


def test_challenge_response_user_login(
    user_with_challenge_response,
    selenium: webdriver,
    do_login,
    check_for_login_success,
):
    user = user_with_challenge_response
    do_login(user["email"], user["password"])
    otp_page = parse_otp_page(selenium,)
    do_otp(otp_page, selenium, user["otp"])
    check_for_login_success()


def test_single_page_user_login(
    user_with_one_stage_login, do_login, check_for_login_success,
):
    user = user_with_one_stage_login
    do_login(user["email"], user["password"] + user["otp"])
    check_for_login_success()


def test_reset_password_flow(
    user_with_challenge_response_and_password_reset,
    selenium: webdriver,
    misp_base_url: str,
    do_login,
    config,
    check_for_login_success,
):
    """
    Test that a user with password reset flag set is able to login and change their password
    """
    user = user_with_challenge_response_and_password_reset
    # Username and password
    do_login(user["email"], user["password"])

    # OTP
    otp_page = parse_otp_page(selenium)
    do_otp(otp_page, selenium, user["otp"])

    # Now we should have arrived at the change password page instead of the main page
    check_for_login_success("/users/change_pw")
    new_password = "NewPassword111!"
    do_change_password_page(selenium, misp_base_url, new_password)

    # We should have arrived at the user's info page
    misp_user_id = user["misp_user"].id
    user_id_selector = (
        "//div[@class='users view']//td[text()='Id']/following-sibling::td"
    )
    assert selenium.find_element_by_xpath(user_id_selector).text == misp_user_id
    assert selenium.current_url == misp_base_url + f"/users/view/{misp_user_id}"

    # Now we need to log out. Unfortunately the logout button is only visible on the
    # MISP interface if the screen is above a certain width. So we'll avoid depending on that
    # button so that this test is less brittle,
    # logout_button = selenium.find_element_by_css_selector('#topBar a[href="/users/logout"]')
    selenium.get(misp_base_url + "/users/logout")

    assert selenium.current_url == config["pluginurl"] + "/Login"

    # Try to login with the new password
    do_login(user["email"], new_password)

    # OTP
    otp_page = parse_otp_page(selenium)
    do_otp(otp_page, selenium, user["otp"])

    # Logged in?
    check_for_login_success()

