import random

class RSA:
    @staticmethod
    def is_prime(n):
        if n <= 1:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    @staticmethod
    def generate_prime(bits=64):
        primes = []
        while len(primes) < 2:
            num = random.getrandbits(bits)
            num |= 1 << (bits - 1)
            if RSA.is_prime(num):
                if len(primes) == 1 and primes[0] == num:
                    continue
                primes.append(num)
        return primes[0], primes[1]

    @staticmethod
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def mod_inverse(a, m):
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        return x1 + m0 if x1 < 0 else x1

    @staticmethod
    def generate_keys():
        p = 61
        q = 53
        N = p * q
        phi = (p - 1) * (q - 1)
        e = random.randint(1, phi)
        while RSA.gcd(e, phi) != 1:
            e = random.randint(1, phi)
        d = RSA.mod_inverse(e, phi)
        public_key = (e, N)
        private_key = (d, N)
        return public_key, private_key
    
    @staticmethod
    def encrypt(message, public_key):
        e, N = public_key
        encrypted_msg = [pow(ord(char), e, N) for char in message]
        return encrypted_msg

    @staticmethod
    def decrypt(encrypted_msg, private_key):
        d, N = private_key
        decrypted_msg = ''.join([chr(pow(char, d, N)) for char in encrypted_msg])
        return decrypted_msg
