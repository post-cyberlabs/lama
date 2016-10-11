#!/bin/bash
# carriage return
cr=`echo $'\n.'`
cr=${cr%.}


########################################################
########################################################
#                      CHECK SUDO                      #
########################################################
########################################################

if [ "$(id -u)" != "0" ]; then
	echo "Sorry, you are not root."
	exit 1
fi

########################################################
########################################################
#                         LOGO                         #
########################################################
########################################################

echo "
        \`.          \`.
        hd/        -ym.
       :shdy      /Nsoy
       osMsN.     msMhh
       /smymossysodydys
        omMMMMMMMMMMNh\`
       oNMMMMMMMMMMMMNy\`
     \`smmhhMMMMMMMMhhmmy\`
     /MM(  )MMMMMMM(  )M+
      oddhmMMMMMMMMmhddy
     \`+MMMMMMddddMMMMMMo
      \`+NMMMMhddhMMMMMo
        .smMMyddyMMNs.
          \`hmmmmmmo\`
           hMMMMMMs
           yMMMMMMs\`
           yMMMMMMy\`
        .++mMMMMMMdo+.
      +dMMsMMMMMMMMyMMd/
    -mMMMyNMMMMMMMMNhMMMm-
   :MMMMMMMMMMMMMMMMMMMMMM:
  \`NMMMMMMM        MMMMMMMMN\`
  /MMMMMMMM  LAMA  MMMMMMMM/
  +MMMMMMMM        MMMMMMMM+
  .MMMMMMMMMMMMMMMMMMMMMMMM.
   yMMMMMMMMMMMMMMMMMMMMMMo
    yMMMMMMMMMMMMMMMMMMMMo
     :dmdddddMMMMdddddmh-
      \`dMoMMMsNMsNMMoMd\`
      .ho/ddho:/ohdd/oh-
"

########################################################
########################################################
#                        GETOPT                        #
########################################################
########################################################

interactive=false

all_install=true
all_force=false
lama_install=false
docker_install=false
db_install=false
rmq_install=false
ftp_install=false

ftp_username=false
ftp_password=false
db_name=false
db_username=false
db_password=false

verbose=false


## FLAGS
# i/interactive : interactive questions
# a/all : full installation
# l/lama : install lama
# d/docker : install docker
# p/postgresql : install postgreqsl
# r/rmq : install rabbitMQ
# f/ftp : install ftp

## OPTIONS FTP
# ftpuser
# ftppasswd

# OPTIONS DB
# dbbase
# dbuser
# dbpasswd



# read the options
TEMP=`getopt -o ialdprfv --long interactive,all,lama,docker,postgresql,rmq,ftp,verbose,ftpuser::,ftppasswd::,dbbase::,dbuser::,dbpasswd:: -n 'install.sh' -- "$@"`

eval set -- "$TEMP"

# extract options and their arguments into variables.
while true ; do
  case "$1" in
    --ftpuser)
      case "$2" in
        "") ftp_username='lama_ftp' ; shift 2 ;;
        *) ftp_username=$2 ; shift 2 ;;
      esac ;;
    --ftppasswd)
      case "$2" in
        "") ftp_password=false ; shift 2 ;;
        *) ftp_password=$2 ; shift 2 ;;
      esac ;;
    --dbbase)
      case "$2" in
        "") db_name='lama' ; shift 2 ;;
        *) db_name=$2 ; shift 2 ;;
      esac ;;

    --dbuser)
      case "$2" in
        "") db_username='lama_db' ; shift 2 ;;
        *) db_username=$2 ; shift 2 ;;
      esac ;;

    --dbpasswd)
      case "$2" in
        "") db_password=false ; shift 2 ;;
        *) db_password=$2 ; shift 2 ;;
      esac ;;

    -i|--interactive)
      interactive=true ; shift ;;

    -a|--all)
      all_force=true ;
      all_install=true ; shift ;;

    -l|--lama)
      all_install=false ;
      lama_install=true ; shift ;;
    -d|--docker)
      all_install=false ;
      docker_install=true ; shift ;;
    -p|--postgresql)
      all_install=false ;
      db_install=true ; shift ;;
    -r|--rmq)
      all_install=false ;
      rmq_install=true ; shift ;;
    -f|--ftp)
      all_install=false ;
      ftp_install=true ; shift ;;
    -v|--verbose)
      verbose=true ; shift ;;


    --) shift ; break ;;
    *) echo "Internal error!" ; exit 1 ;;
  esac
done

# if -a and other -> force all
if [ "$all_force" = true ]
then
  all_install=true
fi

# verbose level
verbose_level="/dev/null"
if [ "$verbose" = true ]
then
  echo "verbose"
  verbose_level="/dev/stdout"
fi

#recap 1
{
  echo "interactive = $interactive"
  echo "all = $all_install"
  echo "all_force = $all_force"
  echo "lama = $lama_install"
  echo "docker = $docker_install"
  echo "postgresql = $db_install"
  echo "rmq = $rmq_install"
  echo "ftp = $ftp_install"
  echo "ftp_username = $ftp_username"
  echo "ftp_password = $ftp_password"
  echo "db_name = $db_name"
  echo "db_username = $db_username"
  echo "db_password = $db_password"
} > $verbose_level



########################################################
########################################################
#                     CHECK PARAMS                     #
########################################################
########################################################

# check param if not interactive mode

if [ "$interactive" = false ]
then
  # DATABASE NAME
  if [ \( "$all_install" = true -o "$db_install" = true \) -a "$db_name" = false ]
  then
    read -p "Enter name for db ? $cr" db_name
  fi

  # DATABASE USERNAME
  if [ \( "$all_install" = true -o "$db_install" = true \) -a "$db_username" = false ]
  then
    read -p "Enter username for db server ? $cr" db_username
  fi

  # DATABSE PASSWORD
  if [ \( "$all_install" = true -o "$db_install" = true \) -a "$db_password" = false ]
  then
    read -sp "Enter password for '$db_username' ? $cr" db_password
  fi


  # FTP USER
  if [ \( "$all_install" = true -o "$ftp_install" = true \) -a "$ftp_username" = false ]
  then
    read -p "Enter username for ftp server ? $cr" ftp_username
    read -sp "Enter password for '$ftp_username' ? $cr" ftp_password
  fi

  # FTP PASSWORD
  if [ \( "$all_install" = true -o "$ftp_install" = true \) -a "$ftp_password" = false ]
  then
    read -sp "Enter password for '$ftp_username' ? $cr" ftp_password
  fi
fi


########################################################
########################################################
#                     INFORMATIONS                     #
########################################################
########################################################

if [ "$interactive" = true ]
then
  # resel all install flag
  all_install=false

  echo "Start interactive LAMA installation"

  read -p "Install Lama on this machine ? [Y/n] $cr" choice
  case "$choice" in
    y|Y ) lama_install=true;;
    n|N ) lama_install=false;;
    * ) lama_install=true;;
  esac

  if [ "$lama_install" = true ]
  then
    read -p "Install Docker on this machine ? [Y/n] $cr" choice
    case "$choice" in
      y|Y ) docker_install=true;;
      n|N ) docker_install=false;;
      * ) docker_install=true;;
    esac
  fi


  read -p "Install FTP Server on this machine ? [Y/n] $cr" choice
  case "$choice" in
    y|Y ) ftp_install=true;;
    n|N ) ftp_install=false;;
    * ) ftp_install=true;;
  esac

  if [ "$ftp_install" = true ]
  then
    read -p "Enter username for ftp server ? $cr" ftp_username
    read -sp "Enter password for '$ftp_username' ? $cr" ftp_password
  fi


  read -p "Install RabbitMQ server on this machine ? [Y/n] $cr" choice
  case "$choice" in
    y|Y ) rmq_install=true;;
    n|N ) rmq_install=false;;
    * ) rmq_install=true;;
  esac


  read -p "Install DB on this machine ? [Y/n] $cr" choice
  case "$choice" in
    y|Y ) db_install=true;;
    n|N ) db_install=false;;
    * ) db_install=true;;
  esac

  if [ "$db_install" = true ]
  then
    read -p "Enter name for db ? $cr" db_name
    read -p "Enter username for db server ? $cr" db_username
    read -sp "Enter password for '$db_username' ? $cr" db_password
  fi
fi

########################################################
########################################################
#                       PASSWORD                       #
########################################################
########################################################

# recap 2
{
  echo "interactive = $interactive"
  echo "all = $all_install"
  echo "all_force = $all_force"
  echo "lama = $lama_install"
  echo "docker = $docker_install"
  echo "postgresql = $db_install"
  echo "rmq = $rmq_install"
  echo "ftp = $ftp_install"
  echo "ftp_username = $ftp_username"
  echo "ftp_password = $ftp_password"
  echo "db_name = $db_name"
  echo "db_username = $db_username"
  echo "db_password = $db_password"
} > $verbose_level



########################################################
########################################################
#                    UPDATE/UPGRADE                    #
########################################################
########################################################

echo "UPDATE/UPGRADE"
{
  apt-get -y update
  apt-get upgrade -y
} > $verbose_level

########################################################
########################################################
#                     INSTALLATION                     #
########################################################
########################################################

echo "INSTALLATION"

##############################################
#                   LAMA                     #
##############################################

if [ "$lama_install" = true -o "$all_install" = true ]
then
  echo "INSTALL LAMA"
  {
    apt-get install -y python3 \
      python3-pip \
      curl \
      libjpeg-dev \
      libpq-dev \
      python-dev

    curl https://bootstrap.pypa.io/get-pip.py | sudo python3

    pip3 install   pika \
      configparser \
      python-magic \
      sqlalchemy \
      psycopg2 \
      docopt \
      requests \
      flask \
      ftputil \
      pillow \
      validators

    pip3 install -e git+https://github.com/deepgram/sidomo.git#egg=sidomo
  } > $verbose_level


  if [ "$docker_install" = true -o "$all_install" = true ]
  then

    echo "DOCKER"
    {
      curl -sSL https://get.docker.com/ | sh
      groupadd docker
      gpasswd -a $SUDO_USER docker
      service docker restart
    } > $verbose_level
  fi

fi


##############################################
#                   FTP                      #
##############################################
if [ "$ftp_install" = true -o "$all_install" = true ]
then
  echo "INSTALL ftp_install"
  {
    apt-get install -y vsftpd
    sed -i -e 's/#write_enable=YES/write_enable=YES/g' /etc/vsftpd.conf

    # TODO add
    sed -i -e 's/rsa_cert_file=\/etc\/ssl\/certs\/ssl-cert-snakeoil\.pem/rsa_cert_file=\/etc\/vsftpd\/vsftpd\.pem/g' /etc/vsftpd.conf
    sed -i -e 's/rsa_private_key_file=\/etc\/ssl\/private\/ssl-cert-snakeoil\.key/rsa_private_key_file=\/etc\/vsftpd\/vsftpd\.key/g' /etc/vsftpd.conf
    sed -i -e 's/ssl_enable=NO/ssl_enable=YES/g' /etc/vsftpd.conf
    echo "allow_anon_ssl=YES
    force_local_data_ssl=YES
    force_local_logins_ssl=YES
    ssl_tlsv1=YES
    ssl_sslv2=NO
    ssl_sslv3=NO
    require_ssl_reuse=NO
    max_per_ip=0" | tee --append /etc/vsftpd.conf

    rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
    rsa_private_key_file=/etc/vsftpd/vsftpd.key
    # TODO create cert

    mkdir /etc/vsftpd
    # TODO add LU, Luxembourg, ... automaticaly
    openssl req -x509 -nodes -days 720 -newkey rsa:2048 -keyout /etc/vsftpd/vsftpd.key -out /etc/vsftpd/vsftpd.pem

    mkdir -p /var/ftproot/$ftp_username/storage
    useradd --home /var/ftproot/$ftp_username $ftp_username
    chown $ftp_username:$ftp_username /var/ftproot/$ftp_username/storage
    # echo $ftp_password | passwd $ftp_username --stdin
    echo "$ftp_username:$ftp_password" | chpasswd
    service vsftpd restart
  } > $verbose_level
fi

##############################################
#                   RMQ                     #
##############################################

if [ "$rmq_install" = true -o "$all_install" = true ]
then
  echo "INSTALL rmq_install"
  {
    apt-get install -y rabbitmq-server
    echo "[{rabbit, [{loopback_users, []}]}]." | tee /etc/rabbitmq/rabbitmq.config
    service rabbitmq-server restart
  } > $verbose_level
fi


##############################################
#                    DB                      #
##############################################

if [ "$db_install" = true -o "$all_install" = true ]
then
  echo "INSTALL db_install"
  {
    apt-get install -y postgresql-9.4 \
      postgresql-server-dev-9.4
    sed -i -e 's/#listen_addres = '\''localhost'\''/listen_addres = '\''\*'\''/g' /etc/postgresql/9.4/main/postgresql.conf
    echo "host    all         all         0.0.0.0/0            md5" | tee --append /etc/postgresql/9.4/main/pg_hba.conf

    sudo -u postgres psql -c "CREATE USER $db_username WITH PASSWORD '$db_password';"
    sudo -u postgres psql -c "CREATE DATABASE lama;"
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE lama to $db_username;"

    service postgresql restart
  } > $verbose_level
fi





########################################################
########################################################
#                  POST INSTALLATION                   #
########################################################
########################################################

# END

if [ "$docker_install" = true -o "$all_install" = true ]
then
  echo "You must logoff/logon your user"
fi
