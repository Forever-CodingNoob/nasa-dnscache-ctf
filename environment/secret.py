import hmac
import hashlib
import re
from datetime import datetime
from typing import Optional

secret_key = 'NekoMimiMode'

class Flag:
    prefix = 'NASA2025'

    def __init__(self, const: str):
        self.const: str = const
        self.additional: Optional[str] = None

    @staticmethod
    def get_mac(data: str) -> str:
        # Compute HMAC-SHA256 and return the hexadecimal digest
        return hmac.new(secret_key.encode(), data.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def verify_flag(flag_str: str) -> bool:
        pattern = r'^' + re.escape(Flag.prefix) + r'\{(.+)_(\w+)\}$'
        match = re.match(pattern, flag_str)
        if not match:
            return False

        data, provided_mac = match.groups()
        expected_mac = hmac.new(secret_key.encode(), data.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(provided_mac, expected_mac)

    def __str__(self) -> str:
        return self.compute_flag()

    def compute_flag(self) -> str:
        timestamp = datetime.now().strftime("%H:%M:%S")
        data = self.const + ('_' + self.additional if self.additional is not None else '') + '_' + timestamp
        mac = self.get_mac(data)
        return f"{self.prefix}{{{data}_{mac}}}"

FLAG1 = Flag('NaivePoisoning')
FLAG2 = Flag('KaminskyAttack')

if __name__ == '__main__':
    flag: str = input('Gimme the flag to verify: ').strip()
    print(Flag.verify_flag(flag))
