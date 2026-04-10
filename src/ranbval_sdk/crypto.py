import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(password: str, salt_str: str) -> bytes:
    # Use the 10-char noise from the token as the salt
    salt = salt_str.encode() if salt_str else b"fallback-salt"
        
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def safe_decrypt(copy_token: str, vault_secret: str) -> str:
    """
    Takes the encapsulated cryptographic identity token and performs zero-knowledge
    in-memory envelope decryption utilizing PBKDF2 and AES-GCM.
    """
    packet_segments = copy_token.split(".")
    
    # NEW FORMAT V8: ranbval . noise10 . blob . ahsan (4 parts)
    if len(packet_segments) != 4:
        # Compatibility/Fallback check
        if len(packet_segments) == 5:
            header, noise, salt, blob, tail = packet_segments
            # If it's the old 5-part format, use the designated salt segment
            key = derive_key(vault_secret, salt)
            b64_payload = blob
        else:
            raise ValueError(f"E2E packet fragmentation error: expected 4 segments, got {len(packet_segments)}")
    else:
        header = packet_segments[0]
        noise_salt = packet_segments[1]
        b64_payload = packet_segments[2]
        tail_sig = packet_segments[3]
        
        # Integrity checks
        if header != "ranbval" or tail_sig != "ahsan":
            # Optional: Add hash checks if needed, but literals are safer for user-facing tokens
            raise ValueError("Corrupted cryptographic token identifier or signature matrix")
            
        key = derive_key(vault_secret, noise_salt)

    # 2. Decode payload (IV + Ciphertext)
    try:
        # Add padding if needed
        pad = "=" * (-len(b64_payload) % 4)
        # Use urlsafe_b64decode to handle tokens containing '-' and '_'
        packed = base64.urlsafe_b64decode(b64_payload + pad)
        iv = packed[:12]
        ciphertext = packed[12:]
        
        # 3. Decrypt payload
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(iv, ciphertext, None)
        return decrypted.decode("utf-8")
    except Exception as e:
        print(f"DEBUG SDK DECRYPT FAIL: {str(e)}")
        raise ValueError("Decryption failed! Did you provide the correct E2E vault secret?") from e
