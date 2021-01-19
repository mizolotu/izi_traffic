from requests import Session

if __name__ == '__main__':
    s = Session()
    uri = 'http://localhost:80/setup.php'
    r = s.get(uri)
    for line in r.content.decode().split('\r\n'):
        if 'user_token' in line:
            spl = line.split('value=')
            user_token = spl[1].split('/>')[0][1:-2]
            break
    data_dict = {'create_db': 'Create / Reset Database', 'user_token': user_token}
    r = s.post(uri, data=data_dict)