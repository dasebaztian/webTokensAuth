from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def firmado(llave_privada: ec.EllipticCurvePrivateKey, data: bytes):
    return llave_privada.sign(data, ec.ECDSA(hashes.SHA256())) ##Se hace el firmado

def verificacion(llave_publica, signature: bytes, datos_a_verificar):##signature y datos a verificar deben ser parametros pasados por POST
    try:
        llave_publica.verify(signature, datos_a_verificar, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

