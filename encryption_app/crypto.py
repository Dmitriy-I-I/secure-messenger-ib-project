# crypto.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os
from cryptography.hazmat.primitives import hmac

class MessageEncryption:
    @staticmethod
    def generate_aes_key():
        return os.urandom(32)  # 256-bit key

    @staticmethod
    def encrypt_aes(key, data):
        if isinstance(data, str):
            data = data.encode()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return {
            'iv': iv,
            'ciphertext': ciphertext
        }

    @staticmethod
    def decrypt_aes(key, iv, ciphertext):
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    @staticmethod
    def create_hmac(key, data):
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize()

    @staticmethod
    def verify_hmac(key, data, signature):
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        try:
            h.verify(signature)
            return True
        except:
            return False

class KeyManager:
    @staticmethod
    def generate_rsa_keys():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return private_key, private_key.public_key()

    @staticmethod
    def serialize_private_key(private_key):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @staticmethod
    def serialize_public_key(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def deserialize_private_key(private_key_pem):
        return serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )

    @staticmethod
    def deserialize_public_key(public_key_pem):
        return serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )

    @staticmethod
    def encrypt_key(public_key, key_data):
        return public_key.encrypt(
            key_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt_key(private_key, encrypted_key):
        return private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

class MessageCrypto:
    def __init__(self):
        self.encryption = MessageEncryption()
        self.key_manager = KeyManager()

    def encrypt_message(self, message, receiver_public_key):
        # Генерируем AES ключ для сообщения
        aes_key = self.encryption.generate_aes_key()
        
        # Шифруем сообщение с помощью AES
        encrypted_data = self.encryption.encrypt_aes(aes_key, message)
        
        # Создаем структуру данных для хранения
        message_data = {
            'iv': encrypted_data['iv'],
            'content': encrypted_data['ciphertext']
        }
        
        # Создаем HMAC
        hmac_signature = self.encryption.create_hmac(aes_key, encrypted_data['ciphertext'])
        
        # Шифруем AES ключ с помощью публичного ключа получателя
        encrypted_aes_key = self.key_manager.encrypt_key(receiver_public_key, aes_key)
        
        return {
            'encrypted_key': encrypted_aes_key,
            'iv': message_data['iv'],
            'content': message_data['content'],
            'hmac': hmac_signature
        }

    def decrypt_message(self, encrypted_data, private_key):
        try:
            # Расшифровываем AES ключ
            aes_key = self.key_manager.decrypt_key(
                private_key,
                encrypted_data['encrypted_key']
            )
            
            # Проверяем HMAC
            if not self.encryption.verify_hmac(
                aes_key,
                encrypted_data['content'],
                encrypted_data['hmac']
            ):
                raise ValueError("HMAC verification failed")
            
            # Расшифровываем сообщение
            decrypted_data = self.encryption.decrypt_aes(
                aes_key,
                encrypted_data['iv'],
                encrypted_data['content']
            )
            
            return decrypted_data
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

# Создаем глобальный экземпляр для использования
crypto_manager = MessageCrypto()