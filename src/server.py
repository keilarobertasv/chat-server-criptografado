import socket
import threading
import json
import database as db
from datetime import datetime
import os
import base64
import hashlib

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import (
	load_pem_parameters,
	load_pem_public_key,
	Encoding,
	PublicFormat
)
from cryptography.exceptions import InvalidSignature, InvalidKey

HOST = "0.0.0.0"
PORT = 65432

online_clients = {}
clients_lock = threading.Lock()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
PARAMS_PATH = os.path.join(PROJECT_ROOT, "dh_params.pem")

try:
	with open(PARAMS_PATH, "rb") as f:
		dh_parameters = load_pem_parameters(f.read())
except Exception as e:
	print(f"Erro fatal: Não foi possível carregar 'dh_params.pem'.")
	print(f"Verifique se o arquivo está em: {PARAMS_PATH}")
	print("Execute 'generate_dh_params.py' primeiro.")
	exit(1)

def _encrypt(plaintext_json_str, aes_key, hmac_key):
	if not aes_key or not hmac_key:
		raise Exception("Sessão de criptografia não estabelecida.")

	padder = PKCS7(algorithms.AES.block_size).padder()
	padded_data = padder.update(plaintext_json_str.encode('utf-8')) + padder.finalize()

	iv = os.urandom(algorithms.AES.block_size // 8)

	cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
	encryptor = cipher.encryptor()
	ciphertext = encryptor.update(padded_data) + encryptor.finalize()

	h = hmac.HMAC(hmac_key, hashes.SHA256())
	h.update(iv + ciphertext)
	mac = h.finalize()

	encrypted_payload = {
		"iv": base64.b64encode(iv).decode('utf-8'),
		"ct": base64.b64encode(ciphertext).decode('utf-8'),
		"mac": base64.b64encode(mac).decode('utf-8')
	}

	return json.dumps(encrypted_payload).encode('utf-8')

def _decrypt(encrypted_payload_bytes, aes_key, hmac_key):
	if not aes_key or not hmac_key:
		raise Exception("Sessão de criptografia não estabelecida.")

	try:
		wrapper = json.loads(encrypted_payload_bytes.decode('utf-8'))
		iv = base64.b64decode(wrapper['iv'])
		ciphertext = base64.b64decode(wrapper['ct'])
		received_mac = base64.b64decode(wrapper['mac'])

		h = hmac.HMAC(hmac_key, hashes.SHA256())
		h.update(iv + ciphertext)
		h.verify(received_mac)

		cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
		decryptor = cipher.decryptor()
		padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

		unpadder = PKCS7(algorithms.AES.block_size).unpadder()
		plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

		return plaintext.decode('utf-8')

	except (InvalidSignature, KeyError, json.JSONDecodeError, Exception):
		return None

def _remove_online_by_socket(sock):
	with clients_lock:
		for uname, (s, a, h) in list(online_clients.items()):
			if s is sock:
				try:
					s.shutdown(socket.SHUT_RDWR)
				except:
					pass
				try:
					s.close()
				except:
					pass
				del online_clients[uname]

def handle_client(client_socket, address):
	current_user = None

	session_aes_key = None
	session_hmac_key = None
	auth_challenge_details = {}
	buffer = b""

	try:
		while True:
			data = client_socket.recv(4096)
			if not data:
				break

			buffer += data

			while b'\n' in buffer:
				payload_bytes, buffer = buffer.split(b'\n', 1)
				if not payload_bytes:
					continue

				message = None
				action = None

				if not session_aes_key:
					try:
						message = json.loads(payload_bytes.decode('utf-8'))
					except json.JSONDecodeError:
						print(f"Erro: JSON inválido recebido durante o handshake de {address}")
						continue
				else:
					decrypted_json_str = _decrypt(payload_bytes, session_aes_key, session_hmac_key)

					if not decrypted_json_str:
						print(f"ALERTA DE SEGURANÇA: HMAC inválido de {address}. Pacote descartado.")
						continue

					try:
						message = json.loads(decrypted_json_str)
					except json.JSONDecodeError:
						print(f"Erro: JSON descriptografado inválido de {address}")
						continue

				action = message.get("action")

				try:
					if action == "handshake":
						if session_aes_key:
							continue
						payload = message.get("payload", {})
						client_public_key_pem = payload.get("dhe_public_key")
						client_salt_b64 = payload.get("salt")

						if not client_public_key_pem or not client_salt_b64:
							response = {"status": "error", "message": "Handshake inválido."}
							client_socket.sendall(json.dumps(response).encode("utf-8") + b'\n')
							continue

						try:
							client_public_key = load_pem_public_key(client_public_key_pem.encode('utf-8'))
							server_private_key = dh_parameters.generate_private_key()
							server_public_key = server_private_key.public_key()

							shared_secret = server_private_key.exchange(client_public_key)

							debug_hash = hashlib.sha256(shared_secret).hexdigest()
							print(f"Hash do Segredo: {debug_hash}")

							salt_bytes = base64.b64decode(client_salt_b64)
							hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt_bytes, info=b'session-key-derivation')
							derived_keys = hkdf.derive(shared_secret)
							session_aes_key = derived_keys[:32]
							session_hmac_key = derived_keys[32:]
							server_public_key_pem = server_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
							response = {"status": "success", "payload": {"server_dhe_public_key": server_public_key_pem.decode('utf-8')}}
							client_socket.sendall(json.dumps(response).encode("utf-8") + b'\n')

						except Exception as e:
							response = {"status": "error", "message": f"Falha no handshake: {e}"}
							client_socket.sendall(json.dumps(response).encode("utf-8") + b'\n')

					elif action == "register":
						payload = message.get("payload", {})
						username = payload.get("username")
						password = payload.get("password")
						public_key = payload.get("public_key")
						if username and password and public_key:
							success, info_message = db.register_user(username, password, public_key)
							if success:
								response = {"status": "success", "message": info_message}
							else:
								response = {"status": "error", "message": info_message}
						else:
							response = {"status": "error", "message": "Usuário, senha ou chave pública não fornecidos."}
						encrypted_response = _encrypt(json.dumps(response), session_aes_key, session_hmac_key)
						client_socket.sendall(encrypted_response + b'\n')

					elif action == "auth_challenge":
						payload = message.get("payload", {})
						username = payload.get("username")

						if not username:
							response = {"status": "error", "message": "Nome de usuário não fornecido."}
							encrypted_response = _encrypt(json.dumps(response), session_aes_key, session_hmac_key)
							client_socket.sendall(encrypted_response + b'\n')
							continue

						public_key_pem = db.get_user_public_key(username)

						if not public_key_pem:
							response = {"status": "error", "message": "Usuário não encontrado ou sem chave pública."}
							encrypted_response = _encrypt(json.dumps(response), session_aes_key, session_hmac_key)
							client_socket.sendall(encrypted_response + b'\n')
							continue
						with clients_lock:
							if username in online_clients:
								old_sock, _, _ = online_clients[username]
								try:
									old_sock.shutdown(socket.SHUT_RDWR)
								except:
									pass
								try:
									old_sock.close()
								except:
									pass
								if username in online_clients:
									del online_clients[username]
						nonce = os.urandom(32)
						auth_challenge_details = {"username": username, "nonce": nonce, "public_key_pem": public_key_pem}
						response = {"type": "auth_challenge", "payload": {"nonce": base64.b64encode(nonce).decode('utf-8')}}
						encrypted_response = _encrypt(json.dumps(response), session_aes_key, session_hmac_key)
						client_socket.sendall(encrypted_response + b'\n')

					elif action == "auth_response":
						if not auth_challenge_details:
							response = {"status": "error", "message": "Nenhum desafio de autenticação pendente."}
							encrypted_response = _encrypt(json.dumps(response), session_aes_key, session_hmac_key)
							client_socket.sendall(encrypted_response + b'\n')
							continue

						payload = message.get("payload", {})
						signature_b64 = payload.get("signature")

						try:
							signature = base64.b64decode(signature_b64)
							nonce = auth_challenge_details["nonce"]
							public_key_pem = auth_challenge_details["public_key_pem"]

							public_key = load_pem_public_key(public_key_pem.encode('utf-8'))

							public_key.verify(
								signature,
								nonce,
								padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
								hashes.SHA256()
							)

							username = auth_challenge_details["username"]
							with clients_lock:
								if username in online_clients:
									response = {"status": "error", "message": "Este usuário já está online."}
									encrypted_response = _encrypt(json.dumps(response), session_aes_key, session_hmac_key)
									client_socket.sendall(encrypted_response + b'\n')
									return
							current_user = username
							with clients_lock:
								online_clients[username] = (client_socket, session_aes_key, session_hmac_key)
							auth_challenge_details = {}
							pending_handshakes = db.get_and_delete_offline_handshakes(current_user)
							if pending_handshakes:
								for sender, public_key in pending_handshakes:
									offer = {"type": "p2p_handshake_offer", "payload": {"username": sender, "public_key": public_key}}
									try:
										encrypted_offer = _encrypt(json.dumps(offer), session_aes_key, session_hmac_key)
										client_socket.sendall(encrypted_offer + b'\n')
									except:
										pass
							status_message = {"type": "status_update", "user": current_user, "status": "online"}
							with clients_lock:
								recipients = list(online_clients.items())
							for user, (client_sock, aes_key, hmac_key) in recipients:
								if client_sock != client_socket:
									try:
										encrypted_status = _encrypt(json.dumps(status_message), aes_key, hmac_key)
										client_sock.sendall(encrypted_status + b'\n')
									except:
										pass

							login_response = {"status": "success", "message": "Login bem-sucedido."}
							encrypted_response = _encrypt(json.dumps(login_response), session_aes_key, session_hmac_key)
							client_socket.sendall(encrypted_response + b'\n')

						except (InvalidSignature, InvalidKey, Exception):
							response = {"status": "error", "message": "Falha na verificação da assinatura. Login negado."}
							encrypted_response = _encrypt(json.dumps(response), session_aes_key, session_hmac_key)
							client_socket.sendall(encrypted_response + b'\n')

					elif action == "get_public_key":
						if current_user:
							payload = message.get("payload", {})
							target_username = payload.get("username")
							if not target_username:
								response = {"status": "error", "message": "Nome de usuário do destinatário não fornecido."}
								encrypted_response = _encrypt(json.dumps(response), session_aes_key, session_hmac_key)
								client_socket.sendall(encrypted_response + b'\n')
								continue
							public_key_b = db.get_user_public_key(target_username)
							if not public_key_b:
								response = {"status": "error", "message": f"Usuário '{target_username}' não encontrado ou sem chave pública."}
								encrypted_response = _encrypt(json.dumps(response), session_aes_key, session_hmac_key)
								client_socket.sendall(encrypted_response + b'\n')
								continue
							response_to_a = {"type": "public_key_response", "payload": {"username": target_username, "public_key": public_key_b}}
							encrypted_response_to_a = _encrypt(json.dumps(response_to_a), session_aes_key, session_hmac_key)
							client_socket.sendall(encrypted_response_to_a + b'\n')
							public_key_a = db.get_user_public_key(current_user)
							with clients_lock:
								recipient_session = online_clients.get(target_username)
							if recipient_session and public_key_a:
								recipient_socket, recipient_aes_key, recipient_hmac_key = recipient_session
								response_to_b = {"type": "p2p_handshake_offer", "payload": {"username": current_user, "public_key": public_key_a}}
								try:
									encrypted_response_to_b = _encrypt(json.dumps(response_to_b), recipient_aes_key, recipient_hmac_key)
									recipient_socket.sendall(encrypted_response_to_b + b'\n')
								except:
									db.store_offline_handshake(target_username, current_user, public_key_a)
							else:
								if public_key_a:
									db.store_offline_handshake(target_username, current_user, public_key_a)

					elif action == "get_contact_list":
						if current_user:
							all_users = db.get_all_users()
							with clients_lock:
								online_users = list(online_clients.keys())
							contact_list_message = {"type": "contact_list", "all_users": all_users, "online_users": online_users}
							encrypted_response = _encrypt(json.dumps(contact_list_message), session_aes_key, session_hmac_key)
							client_socket.sendall(encrypted_response + b'\n')

					elif action == "get_offline_messages":
						if current_user:
							offline_msgs = db.get_and_delete_offline_messages(current_user)
							if offline_msgs:
								for msg in offline_msgs:
									sender, text, timestamp = msg
									offline_msg_data = {"type": "offline_message", "sender": sender, "text": text, "timestamp": timestamp}
									encrypted_response = _encrypt(json.dumps(offline_msg_data), session_aes_key, session_hmac_key)
									client_socket.sendall(encrypted_response + b'\n')

					elif action == "send_message":
						payload = message.get("payload", {})
						recipient = payload.get("recipient")
						text = payload.get("text")

						if not current_user:
							response = {"status": "error", "message": "Faça login antes de enviar mensagens."}
							encrypted_response = _encrypt(json.dumps(response), session_aes_key, session_hmac_key)
							client_socket.sendall(encrypted_response + b'\n')
							continue

						if recipient and text:
							timestamp = datetime.now().strftime("%H:%M")
							with clients_lock:
								recipient_session = online_clients.get(recipient)
							if recipient_session:
								recipient_socket, recipient_aes_key, recipient_hmac_key = recipient_session
								forward_message = {"type": "new_message", "sender": current_user, "text": text, "timestamp": timestamp}
								try:
									encrypted_forward = _encrypt(json.dumps(forward_message), recipient_aes_key, recipient_hmac_key)
									recipient_socket.sendall(encrypted_forward + b'\n')
								except:
									db.store_offline_message(recipient, current_user, text)
							else:
								db.store_offline_message(recipient, current_user, text)

					elif action == "typing_event":
						payload = message.get("payload", {})
						recipient = payload.get("recipient")
						event_type = payload.get("event_type")

						if current_user and recipient and event_type:
							with clients_lock:
								recipient_session = online_clients.get(recipient)
							if recipient_session:
								recipient_socket, recipient_aes_key, recipient_hmac_key = recipient_session
								event_message = {"type": "typing_indicator", "sender": current_user, "event_type": event_type}
								try:
									encrypted_event = _encrypt(json.dumps(event_message), recipient_aes_key, recipient_hmac_key)
									recipient_socket.sendall(encrypted_event + b'\n')
								except:
									pass
				except Exception as e:
					print(f"Erro ao processar ação {action} para {address}: {e}")
					try:
						response = {"status": "error", "message": "Erro interno do servidor."}
						encrypted_response = _encrypt(json.dumps(response), session_aes_key, session_hmac_key)
						client_socket.sendall(encrypted_response + b'\n')
					except:
						pass

	except ConnectionResetError:
		pass
	finally:
		_remove_online_by_socket(client_socket)
		if current_user:
			with clients_lock:
				if current_user in online_clients:
					del online_clients[current_user]

					if session_aes_key:
						status_message = {"type": "status_update", "user": current_user, "status": "offline"}
						with clients_lock:
							recipients = list(online_clients.items())
						for user, (client_sock, aes_key, hmac_key) in recipients:
							try:
								encrypted_status = _encrypt(json.dumps(status_message), aes_key, hmac_key)
								client_sock.sendall(encrypted_status + b'\n')
							except:
								pass
		try:
			client_socket.shutdown(socket.SHUT_RDWR)
		except:
			pass
		try:
			client_socket.close()
		except:
			pass

def main():
	db.init_db()
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((HOST, PORT))
	server.listen()
	print(f"Servidor iniciado em {HOST}:{PORT}")

	while True:
		client_socket, address = server.accept()
		thread = threading.Thread(target=handle_client, args=(client_socket, address))
		thread.start()

if __name__ == "__main__":
	main()
