import random
import math
from hmac import compare_digest
from Crypto.Util import number

class RsaKey:
    def __init__(self, bytes_len) -> None:
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

      if (not self.isPowerOfTwo(bytes_len)): raise Exception("Bytes lenght must be of the form 2^n")
      self.bytes_len = bytes_len
      self.p = number.getPrime(self.bytes_len)
      self.q = number.getPrime(self.bytes_len)

      self.n = self.p * self.q

      lambda_n = (self.p - 1) * (self.q - 1)

      self.e = 65537

      self.d = pow(self.e, -1, lambda_n)

      self.public_key = (self.n, self.e)
      self.private_key = (self.n, self.d)

    def log2(self, x):
      return (math.log10(x) /
            math.log10(2))
    
    def isPowerOfTwo(self, n):
      return (math.ceil(self.log2(n)) == math.floor(self.log2(n)))

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

    def bytes2int(self, raw_bytes: bytes) -> int:
      # Inspired from rsa library
      return int.from_bytes(raw_bytes, "big", signed=False)

    def int2bytes(self, number: int, fill_size: int = 0) -> bytes:
      # Inspired from rsa library
      if number < 0:
        raise ValueError("Number must be an unsigned integer: %d" % number)

      bytes_required = max(1, math.ceil(number.bit_length() / 8))

      if fill_size > 0:
        return number.to_bytes(fill_size, "big")

      return number.to_bytes(bytes_required, "big")
    
    def from_input_to_encrypt(self, input_text):
      input_bytes_len = len(bytes(input_text, 'utf-8'))
      max_length = self.bytes_len//4
      trunc_text = [input_text]

      if input_bytes_len > max_length:
          div = (input_bytes_len // max_length) + 1
          n = input_bytes_len // div
          trunc_text = [input_text[index : index + n] for index in range(0, len(input_text), n)]            

      raw_bytes_list = [bytes(text, 'utf-8') for text in trunc_text]
      payload_list = [self.bytes2int(raw_bytes) for raw_bytes in raw_bytes_list]
      encrypted_number_list = [self.encrypt(payload, self.public_key) for payload in payload_list]
      bytes_block_list = [self.int2bytes(encrypted_number) for encrypted_number in encrypted_number_list]
      return bytes_block_list

    def from_encrypted_to_output(self, encrypted_bytes_list):
      encrypted_number_list = [self.bytes2int(encrypted_bytes) for encrypted_bytes in encrypted_bytes_list]
      decrypted_list = [self.decrypt(encrypted_number, self.private_key) for encrypted_number in encrypted_number_list]
      output = [self.int2bytes(decrypted).decode("utf-8") for decrypted in decrypted_list]
      return "".join(output)


if __name__ == "__main__":
  rsa = RsaKey(1024)
  
  print(rsa.public_key)
  print(rsa.private_key)

  entered = input("Encrypt: (enter text)\n")
  encrypted_bytes = rsa.from_input_to_encrypt(entered)
  decrypted_output = rsa.from_encrypted_to_output(encrypted_bytes)

  print(encrypted_bytes)
  print(len(encrypted_bytes[0]))
  print(decrypted_output)
