import socket
import threading
import json
import database as db
from datetime import datetime
import os
import base64
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import (
	load_pem_parameters,
	load_pem_public_key,
	Encoding,
	PublicFormat
)

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

def handle_client(client_socket, address):
	current_user = None
	
	session_aes_key = None
	session_hmac_key = None

	try:
		while True:
			data = client_socket.recv(1024)
			if not data:
				break
			
			try:
				messages_str = data.decode('utf-8').replace('}{', '}\n{')
				for single_msg_str in messages_str.split('\n'):
					if not single_msg_str:
						continue
					message = json.loads(single_msg_str)
					
					action = message.get("action")

					if not session_aes_key:
						if action == "handshake":
							payload = message.get("payload", {})
							client_public_key_pem = payload.get("dhe_public_key")
							client_salt_b64 = payload.get("salt")

							if not client_public_key_pem or not client_salt_b64:
								response = {"status": "error", "message": "Handshake inválido."}
								client_socket.send(json.dumps(response).encode("utf-8"))
								continue

							try:
								client_public_key = load_pem_public_key(
									client_public_key_pem.encode('utf-8')
								)

								server_private_key = dh_parameters.generate_private_key()
								server_public_key = server_private_key.public_key()

								shared_secret = server_private_key.exchange(client_public_key)
								
								debug_hash = hashlib.sha256(shared_secret).hexdigest()
								print(f"Hash do Segredo: {debug_hash}")

								salt_bytes = base64.b64decode(client_salt_b64)
								
								hkdf = HKDF(
									algorithm=hashes.SHA256(),
									length=64, 
									salt=salt_bytes,
									info=b'session-key-derivation',
								)
								derived_keys = hkdf.derive(shared_secret)
								
								session_aes_key = derived_keys[:32] 
								session_hmac_key = derived_keys[32:] 

								server_public_key_pem = server_public_key.public_bytes(
									Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
								)
								
								response = {
									"status": "success",
									"payload": {
										"server_dhe_public_key": server_public_key_pem.decode('utf-8')
									}
								}
								client_socket.send(json.dumps(response).encode("utf-8"))
								
							except Exception as e:
								response = {"status": "error", "message": f"Falha no handshake: {e}"}
								client_socket.send(json.dumps(response).encode("utf-8"))
								
						else:
							response = {"status": "error", "message": "Handshake necessário."}
							client_socket.send(json.dumps(response).encode("utf-8"))
						
						continue 
					
					if action == "register":
						payload = message.get("payload", {})
						username = payload.get("username")
						password = payload.get("password")
						if username and password:
							success, info_message = db.register_user(username, password)
							if success:
								response = {"status": "success", "message": info_message}
							else:
								response = {"status": "error", "message": info_message}
							client_socket.send(json.dumps(response).encode("utf-8"))
						else:
							response = {"status": "error", "message": "Usuário ou senha não fornecidos."}
							client_socket.send(json.dumps(response).encode("utf-8"))
					
					elif action == "login":
						payload = message.get("payload", {})
						username = payload.get("username")
						password = payload.get("password")

						if username and password:
							if db.check_user_credentials(username, password):
								with clients_lock:
									if username in online_clients:
										response = {"status": "error", "message": "Este usuário já está online."}
										client_socket.send(json.dumps(response).encode("utf-8"))
										return 

								current_user = username
								online_clients[username] = client_socket
								
								status_message = {"type": "status_update", "user": current_user, "status": "online"}
								for user, client in online_clients.items():
									if client != client_socket:
										try:
											client.send(json.dumps(status_message).encode("utf-8"))
										except:
											pass
								
								login_response = {"status": "success", "message": "Login bem-sucedido."}
								client_socket.send(json.dumps(login_response).encode("utf-8"))
							else:
								response = {"status": "error", "message": "Usuário ou senha inválidos."}
								client_socket.send(json.dumps(response).encode("utf-8"))
						else:
							response = {"status": "error", "message": "Usuário ou senha não fornecidos."}
							client_socket.send(json.dumps(response).encode("utf-8"))

					elif action == "store_public_key":
						if current_user:
							payload = message.get("payload", {})
							public_key = payload.get("public_key")
							
							if public_key:
								success, info_message = db.store_public_key(current_user, public_key)
								if success:
									response = {"status": "success", "message": info_message}
								else:
									response = {"status": "error", "message": info_message}
							else:
								response = {"status": "error", "message": "Chave pública não fornecida no payload."}
							
							client_socket.send(json.dumps(response).encode("utf-8"))
						
						else:
							response = {"status": "error", "message": "Faça login antes de enviar uma chave."}
							client_socket.send(json.dumps(response).encode("utf-8"))

					elif action == "get_contact_list":
						if current_user:
							all_users = db.get_all_users()
							with clients_lock:
								online_users = list(online_clients.keys())
							
							contact_list_message = {
								"type": "contact_list",
								"all_users": all_users,
								"online_users": online_users
							}
							client_socket.send(json.dumps(contact_list_message).encode("utf-8"))

					elif action == "get_offline_messages":
						if current_user:
							offline_msgs = db.get_and_delete_offline_messages(current_user)
							if offline_msgs:
								for msg in offline_msgs:
									sender, text, timestamp = msg
									offline_msg_data = {
										"type": "offline_message",
										"sender": sender,
										"text": text,
										"timestamp": timestamp
									}
									client_socket.send(json.dumps(offline_msg_data).encode("utf-8"))
					
					elif action == "send_message":
						payload = message.get("payload", {})
						recipient = payload.get("recipient")
						text = payload.get("text")

						if not current_user:
							response = {"status": "error", "message": "Faça login antes de enviar mensagens."}
							client_socket.send(json.dumps(response).encode("utf-8"))
							continue
						
						if recipient and text:
							timestamp = datetime.now().strftime("%H:%M")
							with clients_lock:
								recipient_socket = online_clients.get(recipient)
							
							if recipient_socket:
								forward_message = {
									"type": "new_message",
									"sender": current_user,
									"text": text,
									"timestamp": timestamp
								}
								recipient_socket.send(json.dumps(forward_message).encode("utf-8"))
							else:
								db.store_offline_message(recipient, current_user, text)

					elif action == "typing_event":
						payload = message.get("payload", {})
						recipient = payload.get("recipient")
						event_type = payload.get("event_type")

						if current_user and recipient and event_type:
							with clients_lock:
								recipient_socket = online_clients.get(recipient)

							if recipient_socket:
								event_message = { 
									"type": "typing_indicator", 
									"sender": current_user, 
									"event_type": event_type 
								}
								recipient_socket.send(json.dumps(event_message).encode("utf-8"))
			
			except json.JSONDecodeError:
				pass
	
	except ConnectionResetError:
	
		pass
	finally:
		if current_user:
			with clients_lock:
				if current_user in online_clients:
					del online_clients[current_user]
					
					status_message = {"type": "status_update", "user": current_user, "status": "offline"}
					for user, client in online_clients.items():
						try:
							client.send(json.dumps(status_message).encode("utf-8"))
						except:
							pass

		client_socket.close()

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