import socket
import struct
import ssl
import smtplib
import os

from dns_tools import get_as


IP_PREFIX = os.getenv("IP_PREFIX", "172.31.")


def get_source_ip(mx_host: str, port: int, timeout: int = 2):
    socket_ip = None

    try:
        import netifaces

        potential_ips = [
            netifaces.ifaddresses(iface)[netifaces.AF_INET][0]["addr"]
            for iface in netifaces.interfaces()
            if netifaces.AF_INET in netifaces.ifaddresses(iface)
        ]
        print("get_source_ip: potential IPs:", potential_ips)
        for x in potential_ips:
            if x.startswith(IP_PREFIX):
                socket_ip = x
                print("get_source_ip: found from netifaces:", socket_ip)
                break
    except Exception:
        pass

    if socket_ip is None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((get_as(mx_host)[0], port))
                socket_ip = s.getsockname()[0]
                print("get_source_ip: found from socket:", socket_ip)
        except Exception:
            pass

    return socket_ip


def get_certificate(mx_host: str, port: int = None, timeout: int = 2):
    socket.setdefaulttimeout(timeout)
    certificate_der = None
    if port is None or type(port) != int:
        return certificate_der

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.ssl_version = ssl.PROTOCOL_TLSv1_2

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        sock.settimeout(timeout)

        result_of_check = False

        with ctx.wrap_socket(sock, server_hostname=mx_host) as sock:
            sock.connect((mx_host, port))
            sock.send(b"STARTTLS\n")
            sock.recv(1000)
            certificate_der = sock.getpeercert(binary_form=True)

        sock.close()
    except Exception as e:
        print(f"get_certificate:e:{mx_host}:{port}:", e)

    return certificate_der


def smtp_tls_check(
    mx_host: str,
    timeout: int = 2,
    with_certificate_check: bool = True,
    incrementer: int = 0,
    results: list = None,
):
    socket.setdefaulttimeout(timeout)

    supports_tls = False
    supporting_port = 0

    for port in [587, 25, 2525]:
        try:
            src_ip = get_source_ip(mx_host, port, timeout)
            if src_ip:
                smtp = smtplib.SMTP(
                    host=mx_host,
                    port=port,
                    timeout=timeout,
                    source_address=(src_ip, (port + 20000 + incrementer)),
                )

                resp = smtp.starttls()
                supports_tls = resp[0] == 220

                smtp.quit()
        except Exception as e:
            print(f"smtp_tls_check:e:{mx_host}:{port}:", e)

        if supports_tls:
            supporting_port = port
            print(f"smtp_tls_check:supporting_port: {port}")
            break

    if with_certificate_check and supports_tls and supporting_port is not None:
        certificate = get_certificate(mx_host, supporting_port, timeout=timeout)
        print(f"certificate:{mx_host}:", certificate)
        supports_tls = certificate is not None

    if type(results) == list:
        results.append(supports_tls)

    return supports_tls
