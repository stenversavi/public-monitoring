FROM python:3
ADD zabbix_sync_to_statuspage.py /
COPY dependencies/certifi-2023.5.7.tar.gz .
COPY dependencies/chardet-5.1.0.tar.gz .
COPY dependencies/idna-3.4.tar.gz .
COPY dependencies/PyYAML-6.0.1.tar.gz .
COPY dependencies/charset-normalizer-3.2.0.tar.gz .
COPY dependencies/requests-2.31.0.tar.gz .
COPY dependencies/urllib3-1.26.16.tar.gz .

RUN tar xzf certifi-2023.5.7.tar.gz && cd certifi-2023.5.7
COPY dependencies/certifi-2023.5.7-py3-none-any.whl .
RUN pip install certifi-2023.5.7-py3-none-any.whl && cd

RUN tar xzf chardet-5.1.0.tar.gz && cd chardet-5.1.0
COPY dependencies/chardet-5.1.0-py3-none-any.whl .
RUN pip install chardet-5.1.0-py3-none-any.whl && cd

RUN tar xzf idna-3.4.tar.gz && cd idna-3.4
COPY dependencies/idna-3.4-py3-none-any.whl .
RUN pip install idna-3.4-py3-none-any.whl && cd

RUN tar xzf PyYAML-6.0.1.tar.gz && cd PyYAML-6.0.1
COPY dependencies/PyYAML-6.0.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl .
RUN pip install PyYAML-6.0.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && cd

RUN tar xzf charset-normalizer-3.2.0.tar.gz && cd charset-normalizer-3.2.0
COPY dependencies/charset_normalizer-3.2.0-py3-none-any.whl .
RUN pip install charset_normalizer-3.2.0-py3-none-any.whl && cd

RUN tar xzf urllib3-1.26.16.tar.gz && cd urllib3-1.26.16
COPY dependencies/urllib3-1.26.16-py2.py3-none-any.whl .
RUN pip install urllib3-1.26.16-py2.py3-none-any.whl && cd

RUN tar xzf requests-2.31.0.tar.gz && cd requests-2.31.0
COPY dependencies/requests-2.31.0-py3-none-any.whl .
RUN pip install requests-2.31.0-py3-none-any.whl && cd

COPY ../zabbix_sync_to_statuspage_conf.yaml /var/opt/zabbix_sync_to_statuspage/zabbix_sync_to_statuspage_conf.yaml
CMD [ "python", "./zabbix_sync_to_statuspage.py", "-c", "/var/opt/zabbix_sync_to_statuspage/zabbix_sync_to_statuspage_conf.yaml", "-v", "-s" ]
