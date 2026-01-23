import os
import hashlib
import hmac
import json
import base64
from typing import List, Tuple, Union
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, Blowfish, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Valid Algorithms
ALGOS = {'aes256', 'blowfish', 'tripledes', 'fernet'}

class EncryptionManager:
    """
    Handles multi-layer encryption and integrity verification.
    """

    @staticmethod
    def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
        """Derive a secure key using PBKDF2-HMAC-SHA256."""
        # Increased to 200,000 iterations for production hardening
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000, dklen=length)

    @staticmethod
    def _generate_signature(data: bytes, key: bytes) -> bytes:
        """Generate HMAC-SHA256 signature."""
        h = hmac.new(key, data, hashlib.sha256)
        return h.digest()

    @staticmethod
    def encrypt_data(content: bytes, password: str, methods: List[str]) -> dict:
        """
        Encrypts data by chaining methods.
        Returns detailed metadata dict including 'ciphertext', hashes, and params.
        """
        if not methods:
            methods = ['fernet']
            
        original_hash = hashlib.sha256(content).hexdigest()
        
        # 1. Generate master salt
        master_salt = get_random_bytes(16)
        
        # 2. Derive master integrity key (200,000 iterations)
        integrity_key = hashlib.pbkdf2_hmac('sha256', password.encode(), master_salt, 200000, 32)
        
        current_data = content
        
        # 3. Apply encryption layers
        for method in methods:
            layer_salt = hashlib.sha256(master_salt + method.encode()).digest()
            key_base = hashlib.pbkdf2_hmac('sha256', password.encode(), layer_salt, 10000, 32)
            
            if method == 'aes256':
                iv = get_random_bytes(16)
                cipher = AES.new(key_base, AES.MODE_CBC, iv)
                encrypted = cipher.encrypt(pad(current_data, AES.block_size))
                current_data = iv + encrypted
                
            elif method == 'blowfish':
                bf_key = key_base[:16] 
                iv = get_random_bytes(8)
                cipher = Blowfish.new(bf_key, Blowfish.MODE_CBC, iv)
                encrypted = cipher.encrypt(pad(current_data, Blowfish.block_size))
                current_data = iv + encrypted
                
            elif method == 'tripledes':
                tdes_key = key_base[:24]
                iv = get_random_bytes(8)
                cipher = DES3.new(tdes_key, DES3.MODE_CBC, iv)
                encrypted = cipher.encrypt(pad(current_data, DES3.block_size))
                current_data = iv + encrypted
                
            elif method == 'fernet':
                f_key = base64.urlsafe_b64encode(key_base)
                f = Fernet(f_key)
                current_data = f.encrypt(current_data)
        
        # 4. HMAC
        signature = EncryptionManager._generate_signature(current_data, integrity_key)
        
        # 5. Pack
        final_blob = b'\x01' + master_salt + signature + current_data
        
        return {
            'ciphertext': final_blob,
            'meta': {
                'original_size': len(content),
                'original_hash': original_hash,
                'encrypted_size': len(final_blob),
                'encrypted_hash': hashlib.sha256(final_blob).hexdigest(),
                'iv_length': 16, 
                'salt_length': 16,
                'iter_count': 200000,
                'integrity_method': 'HMAC-SHA256',
                'methods': methods,
                'preview_hex': final_blob[:32].hex().upper()
            }
        }

    @staticmethod
    def decrypt_data(encrypted_bundle: bytes, password: str, methods: List[str]) -> bytes:
        """
        Decrypts data by reversing verification and methods.
        Throws ValueError on integrity failure.
        """
        if not methods:
            methods = ['fernet']
            
        if len(encrypted_bundle) < 50: # 1 + 16 + 32 + min_data
            raise ValueError("File corrupted or too short")
            
        version = encrypted_bundle[0]
        if version != 1:
            raise ValueError("Unsupported encryption version")
            
        master_salt = encrypted_bundle[1:17]
        stored_signature = encrypted_bundle[17:49]
        encrypted_payload = encrypted_bundle[49:]
        
        # 1. Verify Integrity
        integrity_key = hashlib.pbkdf2_hmac('sha256', password.encode(), master_salt, 200000, 32)
        calculated_signature = EncryptionManager._generate_signature(encrypted_payload, integrity_key)
        
        # Constant time comparison to prevent timing attacks
        if not hmac.compare_digest(stored_signature, calculated_signature):
            raise ValueError("Integrity Check Failed: File has been tampered with or password is wrong.")
            
        current_data = encrypted_payload
        
        # 2. Decrypt layers in REVERSE order
        for method in reversed(methods):
            layer_salt = hashlib.sha256(master_salt + method.encode()).digest()
            key_base = hashlib.pbkdf2_hmac('sha256', password.encode(), layer_salt, 10000, 32)
            
            try:
                if method == 'aes256':
                    iv = current_data[:16]
                    ciphertext = current_data[16:]
                    cipher = AES.new(key_base, AES.MODE_CBC, iv)
                    current_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
                    
                elif method == 'blowfish':
                    bf_key = key_base[:16]
                    iv = current_data[:8]
                    ciphertext = current_data[8:]
                    cipher = Blowfish.new(bf_key, Blowfish.MODE_CBC, iv)
                    current_data = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
                    
                elif method == 'tripledes':
                    tdes_key = key_base[:24]
                    iv = current_data[:8]
                    ciphertext = current_data[8:]
                    cipher = DES3.new(tdes_key, DES3.MODE_CBC, iv)
                    current_data = unpad(cipher.decrypt(ciphertext), DES3.block_size)
                    
                elif method == 'fernet':
                    f_key = base64.urlsafe_b64encode(key_base)
                    f = Fernet(f_key)
                    current_data = f.decrypt(current_data)
            except Exception as e:
                raise ValueError(f"Decryption failed at layer {method}: {str(e)}")
                
        return current_data
