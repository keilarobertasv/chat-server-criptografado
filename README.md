# 📡 Chat Server

## 📖 Descrição
O **Servidor** é responsável por gerenciar usuários, autenticação, conexões simultâneas e o roteamento de mensagens em tempo real.  
Ele utiliza **sockets TCP/IP** e **multithreading** para suportar múltiplos clientes conectados.
Agora, o projeto passa a ter criptografia de ponta a ponta.

*[Versão anterior (sem criptografia)](https://github.com/keilarobertasv/chat-server)*

---

## ⚙️ Funcionalidades
- Registro e autenticação de usuários  
- Lista de contatos com status online/offline  
- Roteamento de mensagens em tempo real  
- Armazenamento de mensagens quando o usuário está offline  
- Entrega imediata das mensagens armazenadas quando o usuário se reconecta  
- Gerenciamento de múltiplos clientes via threads  

---

## 🏗️ Arquitetura
- **Servidor TCP/IP** baseado em threads  
- **Banco de Dados (SQLite)** para armazenar usuários e mensagens offline  
- Comunicação via **pacotes JSON** 

---

## 🚀 Como Executar

### 🔧 Pré-requisitos
- Python 3  
- SQLite

### Clonar o repositório
git clone https://github.com/keilarobertasv/chat-server-criptografado
cd chat-server

### Instalar dependências
pip install -r requirements.txt

### Executar servidor
python server.py



