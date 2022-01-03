import random

class RsaKey:
    def __init__(self) -> None:
        """Build an RSA key.
        :Keywords:
          n : integer
            The modulus.
          e : integer
            The public exponent.
          d : integer
            The private exponent. Only required for private keys.
          p : integer
            The first factor of the modulus. Only required for private keys.
          q : integer
            The second factor of the modulus. Only required for private keys.
        """

        primes = [i for i in range(1000, 10000) if self._is_prime(i)]
        self.p = random.choice(primes)
        primes.remove(self.p)
        self.q = random.choice(primes)

        self.n = self.p * self.q

        lambda_n = (self.p - 1) * (self.q - 1)

        self.e = 65537

        self.d = pow(self.e, -1, lambda_n)

        self.public_key = (self.n, self.e)
        self.private_key = (self.n, self.d)

    def _is_prime(self, n):
        return n > 1 and all(n % i for i in range(2, int(n ** 0.5) + 1))

    def _gcd(self, p, q):
    # Create the gcd of two positive integers.
        while q != 0:
            p, q = q, p % q
        return p

    def encrypt(self, m, public_key):
        n = public_key[0]
        e = public_key[1]
        return pow(m, e, n)

    def decrypt(self, c, private_key):
        n = private_key[0]
        d = private_key[1]
        return pow(c, d, n)

    def bytes2int(raw_bytes: bytes) -> int:
        # Inspired from rsa library
        return int.from_bytes(raw_bytes, "big", signed=False)
    
    def from_input_to_encrypt(self, input_text):
        ascii_values = [byte for byte in bytes(input_text, 'ascii')]
        encrypted_number_list = [self.encrypt(ascii_num, self.public_key) for ascii_num in ascii_values]
        return encrypted_number_list

    def from_encrypted_to_output(self, encrypted_number_list):
        decrypted_number_list = [self.decrypt(encrypted_number, self.private_key) for encrypted_number in encrypted_number_list]
        char_list = [chr(decrypted_number) for decrypted_number in decrypted_number_list]
        return char_list


if __name__ == "__main__":
    rsa = RsaKey()
    
    print(rsa.public_key)
    print(rsa.private_key)

    entered = input("Encrypt: (enter text)\n")
    encrypted_number_list = rsa.from_input_to_encrypt(entered)
    decrypted_list = rsa.from_encrypted_to_output(encrypted_number_list)

    print("".join(decrypted_list))