# Library
# Author Alexander Onofrei
# Creation date: 13-09-2024
from OpenSSL import SSL
import socket
import http.server
import ssl

certificate_path = "../Ressources/certificates_keys/server.crt"
keyfile_path = "../Ressources/certificates_keys/server.key"
response = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 13\r\n"
    "\r\n"
    "Hello, World!"
)

def start_HTTPS_server_using_ssl_import(host, port):
    httpd = http.server.HTTPServer((host, port),http.server.SimpleHTTPRequestHandler)
    
    #httpd.socket = ssl.wrap_socket(httpd.socket,certfile=certificate_path,
    #                               keyfile=keyfile_path, server_side=True, ssl_version=ssl.PROTOCOL_TLS)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certificate_path,keyfile=keyfile_path)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    httpd.serve_forever()


# Function to handle client connections
def handle_client(conn):
    print("Client connected")
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                break
            print("Received:", data.decode())
            # Proper HTTP response format with headers and content
            conn.sendall(response.encode())
        except SSL.Error as e:
            print("SSL error:", e)
            break
        finally:
            if conn:
                print("Client disconnected")
                # Close the connection properly
                conn.shutdown()
                conn.close()

def start_HTTPS_server_using_openssl_import(host, port):
    # Set up the SSL context
    context = SSL.Context(SSL.TLS_METHOD)
    context.use_privatekey_file(keyfile_path)
    context.use_certificate_file(certificate_path)

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(5)
    while True:
        client_socket, client_addr = sock.accept()
        print(f"Connection from {client_addr}")
        # Wrap the socket with SSL/TLS
        ssl_conn = SSL.Connection(context, client_socket)
        ssl_conn.set_accept_state()  # Set the connection to server mode
        handle_client(ssl_conn)

if __name__ == '__main__':
    start_HTTPS_server_using_ssl_import('localhost', 8443)
    #start_HTTPS_server_using_openssl_import('localhost', 8443)

