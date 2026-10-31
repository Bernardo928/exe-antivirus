"""Simulador INOFENSIVO de comportamento de botnet (usado só nos testes do escudo anti-botnet).

Só usa endereços reservados para documentação (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
que nunca chegam a uma máquina real: as conexões ficam "tentando" (SYN_SENT) e nada é enviado.
Modos:
  worm     tenta Telnet/SSH/SMB em 40 endereços diferentes (varredura para se espalhar)
  beacon   contata o mesmo "servidor" em intervalos regulares (porta IRC 6667)
  listen   abre uma porta de entrada 4444 na rede (backdoor)
  c2 IP    conecta-se ao IP informado (servidor de comando)
  quiet    só dorme (controle negativo)
"""
import socket
import sys
import time


def _try(ip, port, keep):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    try:
        s.connect((ip, port))
    except (BlockingIOError, OSError):
        pass
    keep.append(s)


def main():
    mode = sys.argv[1]
    duration = float(sys.argv[2]) if len(sys.argv) > 2 else 30
    keep = []
    end = time.time() + duration
    if mode == "worm":
        for i in range(40):
            _try(f"198.51.100.{i + 1}", (23, 22, 445)[i % 3], keep)
    elif mode == "beacon":
        interval = float(sys.argv[3]) if len(sys.argv) > 3 else 2.0
        while time.time() < end:
            _try("203.0.113.66", 6667, keep)
            time.sleep(interval)
    elif mode == "listen":
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", int(sys.argv[3]) if len(sys.argv) > 3 else 4444))
        s.listen()
        keep.append(s)
    elif mode == "c2":
        _try(sys.argv[3], 443, keep)
    sys.stdout.write("pronto\n")
    sys.stdout.flush()
    while time.time() < end:
        time.sleep(0.2)


if __name__ == "__main__":
    main()
