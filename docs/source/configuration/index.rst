Configuration
=============

The main config file is ``lama/conf/project.conf``


**DATABASE** (mandatory for all parts) :

- **host** : IP or domain name of the DB server
- **database** : Name of the database
- **user** : Name of DB user
- **password** : Password of DB user


**FTP** (mandatory for all parts) :

- **host** : IP or domain name of the FTP server
- **root_dir** : Directory for FTP user, relative to his home
- **user** : Name of FTP user
- **password** : Password of FTP user


**RABBITMQ** (mandatory for all parts) :

- host :  IP or domain name of the RMQ server


**MAIL_ALERT** (mandatory for all parts) :

- **enabled** : 'True' or 'False' if you want mail alert or not
- **user** : User of the mail address
- **password** : Password of the mail address
- **server** : IP or domain name of the SMTP mail server
- **smtp_port** : Port of the SMTP mail server
- **sender** : Email address of the sender (it's like <user>@<server>)
- **recipients** : Recipients for mail, separated by comma


**LAMA** (mandatory for all parts) :

- **host** : IP or domain name for the lama Web/API access
- **port** : Port for the HTTP lama Web/API access (if no reverse proxy, it's the same than flask_listen_port on API section)


**API** (mandatory for lama_api) :

- **upload_folder** : Upload folder for flask (by default uploads)
- **flask_listen_host** : Flask listen port
- **flask_listen_port** : Flask listen port


**MODULES** (Optional for lama_analyzer) :

- **white_list** : List of enabled module, only those modules are running
- **black_list** : List of disabled module, all module except those ones are running


**MAIL_INPUT** (Mandatory for lama_mail) :

- **user** : User of the mail address
- **password** : Password of the user
- **server** : IP or domain name of the IMAP mail server
- **port** : Port of the IMAP mail server
