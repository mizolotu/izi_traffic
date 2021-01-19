FROM ubuntu:18.04

RUN apt-get update && \
    apt-get upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    debconf-utils && \
    echo mariadb-server mysql-server/root_password password vulnerables | debconf-set-selections && \
    echo mariadb-server mysql-server/root_password_again password vulnerables | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apache2 \
    mariadb-server \
    php \
    php-mysql \
    php-pgsql \
    php-pear \
    php-gd \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY php.ini /etc/php5/apache2/php.ini
COPY dvwa /var/www/html

COPY config.inc.php /var/www/html/config/

RUN chown www-data:www-data -R /var/www/html && \
    rm /var/www/html/index.html

RUN service mysql start && \
    sleep 3 && \
    mysql -uroot -pvulnerables -e "CREATE USER app@localhost IDENTIFIED BY 'vulnerables';CREATE DATABASE dvwa;GRANT ALL privileges ON dvwa.* TO 'app'@localhost;"

RUN apt update
RUN apt install -y python3 python3-pip nano net-tools openssh-server

RUN pip3 install flask flask_script flask_sqlalchemy pygeoip pyscreenshot pillow scapy numpy netifaces paramiko
RUN pip3 install https://github.com/google-coral/pycoral/releases/download/release-frogfish/tflite_runtime-2.5.0-cp36-cp36m-linux_x86_64.whl

ADD server.py /usr/src/app/
ADD client.py /usr/src/app/
ADD scapy_utils.py /usr/src/app
ADD generators /usr/src/app/generators
ADD app_utils.py /usr/src/app
ADD api /usr/src/app/api
ADD models.py /usr/src/app/
ADD ares.py /usr/src/app/
ADD agent.py /usr/src/app/
ADD config.py /usr/src/app/
ADD agent.py /usr/src/app/
ADD init_dvwa.py /usr/src/app/
ADD passlist.txt /usr/src/app/
ADD cmdlist.txt /usr/src/app/
ADD urilist.txt /usr/src/app/

WORKDIR /usr/src/app