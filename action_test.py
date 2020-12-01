import socket, sys, os

if __name__ == '__main__':

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print('Failed to create socket')
        sys.exit()

    print('Socket Created')

    remote_ip = sys.argv[1]
    port = 80

    #s.settimeout(1.0)
    s.connect((remote_ip, port))

    print('Socket Connected to ' + remote_ip)

    message = 'GET /DVWA-master/login.php HTTP/1.1\r\nHost: {0}\r\n\r\n'.format(remote_ip)
    print('Sending {0}'.format(message))

    try:
        s.sendall(message.encode('utf-8'))
        print('Send succeeded')
    except socket.error:
        print('Send failed')
        sys.exit()

    reply = s.recv(4096).decode('utf-8')
    lines = reply.split('\r\n')
    for line in lines:
        if 'user_token' in line:
            spl = line.split('value=')
            user_token = spl[1].split('/>')[0][1:-2]
    print('User token: {0}'.format(user_token))

    cookie_list = []
    spl = reply.split('Set-Cookie: ')
    for item in spl[1:]:
        cookie_value = item.split(';')[0]
        if cookie_value not in cookie_list:
            cookie_list.append(cookie_value)
    cookie = ';'.join(cookie_list)

    # post correct

    content = 'username=admin&password=password&Login=Login&user_token={0}'.format(user_token)
    message = 'POST /DVWA-master/login.php HTTP/1.1\r\n' \
              'Host: {0}\r\n' \
              'Cookie: {1}\r\n' \
              'Content-Type: application/x-www-form-urlencoded\r\n' \
              'Content-Length: {2}\r\n\r\n' \
              '{3}'.format(remote_ip, cookie, len(content), content)
    message_encoded = message.encode('utf-8')
    print('Sending {0}'.format(message_encoded))

    try:
        s.sendall(message_encoded)
        print('Send succeeded')
    except socket.error:
        print('Send failed')
        sys.exit()
    try:
        reply = s.recv(4096).decode('utf-8')
        print('Received: {0}'.format(reply))
    except socket.timeout:
        print('timeout')

    # post incorrect

    content = 'username=admin&password=wrongpassword&Login=Login&user_token={0}'.format(user_token)
    message = 'POST /DVWA-master/login.php HTTP/1.1\r\nHost: {0}\r\nCookie: {1}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {2}\r\n\r\n{3}'.format(
        remote_ip, cookie, len(content), content
    )
    message_encoded = message.encode('utf-8')
    print('Sending {0}'.format(message_encoded))

    try:
        s.sendall(message_encoded)
        print('Send succeeded')
    except socket.error:
        print('Send failed')
        sys.exit()
    try:
        reply = s.recv(4096).decode('utf-8')
        print('Received: {0}'.format(reply))
    except socket.timeout:
        print('timeout')


    # pad with random bytes

    nrandom = 10
    content = 'username=admin&password=password&Login=Login&user_token={0}'.format(user_token)
    message = 'POST /DVWA-master/login.php HTTP/1.1\r\nHost: {0}\r\nCookie: {1}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {2}\r\n\r\n{3}'.format(
        remote_ip, cookie, len(content) + nrandom, content
    )
    message_encoded = message.encode('utf-8') + bytearray(os.urandom(nrandom))
    print('Sending {0}'.format(message_encoded))

    try:
        s.sendall(message_encoded)
        print('Send succeeded')
    except socket.error:
        print('Send failed')
        sys.exit()
    try:
        reply = s.recv(4096).decode('utf-8')
        print('Received: {0}'.format(reply))
    except socket.timeout:
        print('timeout')

    # append zero packet

    nzero = 10
    message_encoded = bytearray(nzero)
    print('Sending {0}'.format(message_encoded))

    try:
        s.sendall(message_encoded)
        print('Send succeeded')
    except socket.error:
        print('Send failed')
        sys.exit()
    try:
        reply = s.recv(4096).decode('utf-8')
        print('Received: {0}'.format(reply))
    except socket.timeout:
        print('timeout')

    # append random packet

    nrandom = 10
    message_encoded = bytearray(os.urandom(nrandom))
    print('Sending {0}'.format(message_encoded))

    try:
        s.sendall(message_encoded)
        print('Send succeeded')
    except socket.error:
        print('Send failed')
        sys.exit()
    try:
        reply = s.recv(4096).decode('utf-8')
        print('Received: {0}'.format(reply))
    except socket.timeout:
        print('timeout')