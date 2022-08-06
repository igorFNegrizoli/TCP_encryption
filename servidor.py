import sys
import servidorAES, servidorRSA
import time

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

def testes_cliente(metodo, host, port):
    if metodo == "AES":
        for i in range(10):
            print(f"iteração: {i}")
            dado = servidorAES.servidorAES(host, port)
            print(f'Enviados {dado[0]} em {dado[1]} blocos')
            time.sleep(2)
    elif metodo == "RSA":
        for i in range(10):
            print(f"iteração: {i}")
            dado = servidorRSA.servidorRSA(host, port)
            print(f'Enviados {dado[0]} em {dado[1]} blocos')
            time.sleep(2)
    else:
        print("Entrada invalida\n")
        print("Entradas aceitas: AES || RSA")
    print('Testes de servidor finalizados')

if __name__ == "__main__":
    testes_cliente(sys.argv[1], HOST, PORT)