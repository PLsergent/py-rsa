import math
from Crypto import Random
from Crypto.IO import PEM
from Crypto.Math.Numbers import Integer
from Crypto.PublicKey.RSA import construct
from Crypto.Util import number
from Crypto.Util.asn1 import DerSequence

class RsaKey:
    def __init__(self, bytes_len=1024) -> None:
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

      if (not self.__is_power_of_two(bytes_len)): raise Exception("Bytes lenght must be of the form 2^n")
      self.bytes_len = bytes_len
      self.p = number.getPrime(self.bytes_len)
      self.q = number.getPrime(self.bytes_len)

      self.n = self.p * self.q

      lambda_n = (self.p - 1) * (self.q - 1)

      self.e = 65537

      self.d = pow(self.e, -1, lambda_n)

      self.public_key = (self.n, self.e)
      self.private_key = (self.n, self.d)

      self.__randfunc = Random.get_random_bytes


    def __repr__(self) -> str:
        return f"Public key: {self.public_key}\n########\n"\
               f"Private Key: {self.private_key}"

    def __log2(self, x):
      return (math.log10(x) /
            math.log10(2))
    
    def __is_power_of_two(self, n):
      return (math.ceil(self.__log2(n)) == math.floor(self.__log2(n)))

    def __is_prime(self, n):
      return n > 1 and all(n % i for i in range(2, int(n ** 0.5) + 1))

    def __gcd(self, p, q):
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
      max_length = self.bytes_len // 4
      trunc_text = [input_text]

      # If the input bytes length is greater than the max length we can encrypt at once,
      # we will truncate the text into several part an then encrypt each part
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


    def export_private_key(self):
      # Inspired from pycryptodome
      binary_key = DerSequence([0,
          self.n,
          self.e,
          self.d,
          self.p,
          self.q,
          self.d % (self.p-1),
          self.d % (self.q-1),
          Integer(self.q).inverse(self.p)
        ]).encode()

      pem_str_private = PEM.encode(binary_key, "RSA PRIVATE KEY", None, self.__randfunc)
      return pem_str_private
    

    def export_public_key(self):
      # Inspired from pycryptodome
      binary_key = DerSequence([self.n, self.e]).encode()
      
      pem_str_public = PEM.encode(binary_key, "PUBLIC KEY", None, self.__randfunc)
      return pem_str_public


    def import_private_key(self, extern_key):
      (encoded, marker, enc_flag) = PEM.decode(extern_key, None)
      der = DerSequence().decode(encoded, nr_elements=9, only_ints_expected=True)
      if der[0] != 0:
          raise ValueError("No PKCS#1 encoding of an RSA private key")
      
      rsa_key = construct(der[1:6] + [Integer(der[4]).inverse(der[5])])
      return (rsa_key.n, rsa_key.d)
      

    def import_public_key(self, extern_key):
      (encoded, marker, enc_flag) = PEM.decode(extern_key, None)
      der = DerSequence().decode(encoded, nr_elements=2, only_ints_expected=True)
      rsa_key = construct(der)
      return (rsa_key.n, rsa_key.e)


if __name__ == "__main__":
  rsa = RsaKey(1024)
  
  print(f"\nRSA KEYS : \n{rsa}\n")

  print("#########################################\n")

  entered = input("Encrypt: (enter text)\n")
  encrypted_bytes = rsa.from_input_to_encrypt(entered)
  decrypted_output = rsa.from_encrypted_to_output(encrypted_bytes)

  print(f"\nEncrypted text: {encrypted_bytes}\n")
  print(f"Decrypted text: {decrypted_output}\n")

  print("#########################################\n")

  pem_str_private = rsa.export_private_key()
  print(f"{pem_str_private}\n")

  pem_str_public = rsa.export_public_key()
  print(f"{pem_str_public}\n")

  imported_private_key = rsa.import_private_key(pem_str_private)
  print(f"Imported private key: {imported_private_key}\n")

  imported_public_key = rsa.import_public_key(pem_str_public)
  print(f"Imported public key: {imported_public_key}")