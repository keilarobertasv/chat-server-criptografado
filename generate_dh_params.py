from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

print("Gerando parâmetros DH (2048 bits)...")
parameters = dh.generate_parameters(generator=2, key_size=2048)

print("Salvando parâmetros em 'dh_params.pem'...")
with open("dh_params.pem", "wb") as f:
    f.write(parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    ))

print("Pronto! O arquivo 'dh_params.pem' foi criado.")