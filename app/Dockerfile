FROM amazonlinux

RUN yum update -y && yum clean all && yum install -y python3-devel openssl-devel zlib-devel gcc && yum clean all && rm -rf /var/cache/yum

RUN mkdir -p /var/www

WORKDIR /var/www

COPY requirements.txt requirements.txt
COPY uwsgi.ini uwsgi.ini
RUN pip3 install --no-cache-dir -r requirements.txt

WORKDIR /var/www/src
CMD ["uwsgi", "--ini", "/var/www/uwsgi.ini"]