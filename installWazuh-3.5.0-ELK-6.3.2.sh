#!/bin/sh
#Debes primero modificar la linea donde esta el PASSWORD que usaran los agentes para autenticarse.
yum update -y
yum upgrade -y
yum -y install net-tools
cat > /etc/yum.repos.d/wazuh.repo <<\EOF
[wazuh_repo]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/3.x/yum/
protect=1
EOF
curl -Lo jre-8u181-linux-x64.rpm --header "Cookie: oraclelicense=accept-securebackup-cookie" "https://download.oracle.com/otn-pub/java/jdk/8u181-b13/96a7b8442fe848ef90c96a2fad6ed6d1/jre-8u181-linux-x64.rpm"
rpm -ivh jre-8u181-linux-x64.rpm
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
echo "[logstash-6.x]
name=Elastic repository for 6.x packages
baseurl=https://artifacts.elastic.co/packages/6.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md" > /etc/yum.repos.d/elasticsearch.repo
yum update -y
yum -y install elasticsearch-6.3.2 kibana-6.3.2 logstash-6.3.2
systemctl enable logstash.service
systemctl enable kibana.service
systemctl enable elasticsearch.service
/usr/share/logstash/bin/logstash-plugin install logstash-output-email
echo "cluster.name: elk01
node.name: elk01-nodo01
bootstrap.memory_lock: true
network.host: 127.0.0.1" >> /etc/elasticsearch/elasticsearch.yml
sed -i 's/-Xms1g/-Xms32g/g' /etc/elasticsearch/jvm.options
sed -i 's/-Xmx1g/-Xmx32g/g' /etc/elasticsearch/jvm.options
echo "ES_HOME=/usr/share/elasticsearch
CONF_DIR=/etc/elasticsearch
DATA_DIR=/var/lib/elasticsearch
LOG_DIR=/var/log/elasticsearch
PID_DIR=/var/run/elasticsearch
ES_STARTUP_SLEEP_TIME=5
MAX_OPEN_FILES=9965536" >> /etc/sysconfig/elasticsearch
echo 'server.port: 5601
server.host: "localhost"
server.name: "ELK01"
elasticsearch.url: "http://localhost:9200"
elasticsearch.preserveHost: true
kibana.index: ".kibana"
kibana.defaultAppId: "discover"' >> /etc/kibana/kibana.yml
service elasticsearch start
service kibana start
cat > /etc/yum.repos.d/wazuh.repo <<\EOF
[wazuh_repo]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/3.x/yum/
protect=1
EOF
yum -y update
yum -y install wazuh-manager
service wazuh-manager status
curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -
yum install -y nodejs
python --version
netstat -tapn | grep LISTEN
yum -y install wazuh-api
service wazuh-api status
curl -s https://raw.githubusercontent.com/wazuh/wazuh/3.5/extensions/elasticsearch/wazuh-elastic6-template-alerts.json | curl -XPUT 'http://localhost:9200/_template/wazuh' -H 'Content-Type: application/json' -d @-
curl -so /etc/logstash/conf.d/01-wazuh.conf https://raw.githubusercontent.com/wazuh/wazuh/3.5/extensions/logstash/01-wazuh-local.conf
chown logstash:logstash /etc/logstash/conf.d/01-wazuh.conf
usermod -a -G ossec logstash
systemctl daemon-reload
export NODE_OPTIONS="--max-old-space-size=3072"
/usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-3.5.0_6.3.2.zip
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elasticsearch.repo
node /var/ossec/api/configuration/auth/htpasswd -c /var/ossec/api/configuration/auth/user manager
service wazuh-api restart
echo "PASSWORD" > /var/ossec/etc/authd.pass
/var/ossec/bin/ossec-authd -i -P -a
firewall-cmd --permanent --add-port=1515/tcp
firewall-cmd --permanent --add-port=1514/udp
firewall-cmd --reload
service logstash start
service kibana restart
service logstash start
service kibana restart
