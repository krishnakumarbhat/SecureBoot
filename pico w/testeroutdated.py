import time
import network
import socket

def get_address():
    """Gets the IP address of the Pico W board."""
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.connect('sdfg', 'asdf1234')

    while wlan.status() != 3:
        time.sleep(1)

    return wlan.ifconfig()[0]

def serve(address):
    """Serves the web page at the specified address."""
    addr = socket.getaddrinfo(address, 45000)[0][-1]
    s = socket.socket()
    s.bind(addr)
    s.listen(1)

    print('listening on', addr)

    while True:
        cl, addr = s.accept()
        print('client connected from', addr)
        request = cl.recv(1024)
        print('request:', request)

        response = 'HTTP/1.0 200 OK\r\nContent-type: text/html\r\n\r\n'
        response += '<html><body><h1>Pico W HTTP Server</h1></body></html>'

        cl.send(response)
        cl.close()

if __name__ == '__main__':
    address = get_address()
    serve(address)
