import sys
import clienteAES, clienteRSA
import time
import numpy as np
from scipy import stats

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

def conta(data, confidence = 0.95):
    a = 1.0 * np.array(data)
    n = len(a)
    m = np.mean(a)
    se = stats.sem(a)
    h = se * stats.t.ppf((1 + confidence) / 2., n-1)
    return m, m-h, m+h, np.std(a)

def testes_cliente(metodo, host, port):
    tempos = []
    if metodo == "AES":
        for i in range(10):
            print(f"iteração: {i}")
            dado = clienteAES.clienteAES(host, port)
            print(f'Recebidos {dado[1]} em {dado[2]} blocos')
            tempos.append(dado[0])
            time.sleep(2)
    elif metodo == "RSA":
        for i in range(10):
            print(f"iteração: {i}")
            dado = clienteRSA.clienteRSA(host, port)
            print(f'Recebidos {dado[1]} em {dado[2]} blocos')
            tempos.append(dado[0])
            time.sleep(2)
    else:
        print("Entrada invalida\n")
        print("Entradas aceitas: AES || RSA")
    
    dados_tempos = conta(tempos)
    print(f"Media: {dados_tempos[0]} | Intervalo: [{dados_tempos[1]}, {dados_tempos[2]}] | D.P.: {dados_tempos[3]} ")

if __name__ == "__main__":
    testes_cliente(sys.argv[1], HOST, PORT)