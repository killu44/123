#!/bin/bash
# Shell script for automaticaly rollout flags on host

# ln /root/flags/pt/pt.flag /etc/pt.flag

# Usage:
# ./auto_rollout.sh [parameters]
# Parameters:
# -q -noSQL - do not rollout sql flag
# -s -noSSRF - do not rollout ssrf flag
# -r -noRCE - do not rollout rce flag
# -l -noLPE - do not rollout lpe flag
# -p -noPT - do not rollout path traversal flag
# --unacceptable-event - rollout unacceptable event flag
# --unacceptable-event-path [path] - path to malware for unacceptable event flag
# -c --check - only check if all flags are in place (do not rollout)
# -h --help - show help
# -U --user [username] - username for database connection
# -P --password - password for database connection (password will be prompted)
# -D --database [database] - database name for database connection
# -E --engine [engine] - database engine for database connection (mysql, mariadb, postgresql) If not specified - will be detected automatically
# -H --host [host] - database host for database connection (default: localhost)
# -C --cleanup - cleanup all binaries, flags and services (do not affect database)


trap "stty echo; exit" EXIT

function ctrl_c() {
    echo "Terminating..."
    # fix stty
    stty echo
    exit
}


function help {
    echo "Usage:"
    echo "./auto_rollout.sh [parameters]"
    echo "Parameters:"
    echo "-q -noSQL - do not rollout sql flag"
    echo "-s -noSSRF - do not rollout ssrf flag"
    echo "-r -noRCE - do not rollout rce flag"
    echo "-l -noLPE - do not rollout lpe flag"
    echo "-p -noPT - do not rollout path traversal flag"
    echo "--unacceptable-event - rollout unacceptable event flag"
    echo "--unacceptable-event-path [path] - path to malware for unacceptable event flag"
    echo "-c --check - only check if all flags are in place (do not rollout)"
    echo "-h --help - show help"
    echo "-U --user [username] - username for database connection"
    echo "-P --password - password for database connection (password will be prompted)"
    echo "-D --database [database] - database name for database connection"
    echo "-E --engine [engine] - database engine for database connection (mysql, mariadb, postgresql) If not specified - will be detected automatically"
    echo "-H --host [host] - database host for database connection (default: localhost)"
    echo "-P --port [port] - database port for database connection (default: 3306 for mysql/mariadb, 5432 for postgresql)"
    echo "-C --cleanup - cleanup all binaries, flags and services (do not affect database)" 
    exit
}


ONLY_CHECK="false"
NO_SQL="false"
NO_SSRF="false"
NO_RCE="false"
NO_LPE="false"
NO_PT="false"
NO_UE="true"

db_user=""
db_pass=""
db_name=""
db_engine=""
db_host="localhost"
db_port=""

default_ue_path="/tmp/stf-malware"

function prompt_password {
    stty -echo
    read -p "Enter database password: " db_pass; echo
    stty echo
    echo ""
}


# delete all binaries and services if exists
function cleanup {
    if [ -f /root/ssrf_server ]; then
        rm -rf /root/ssrf_server
    fi

    if [ -f /etc/systemd/system/ssrf.service ]; then
        systemctl stop ssrf.service
        systemctl disable ssrf.service
        rm -rf /etc/systemd/system/ssrf.service
    fi

    if [ -f /home/rceflag ]; then
        rm -rf /home/rceflag
    fi

    if [ -f /home/lpeflag ]; then
        rm -rf /home/lpeflag
    fi

    if [ -f /etc/pt.flag ]; then
        rm -rf /etc/pt.flag
    fi

    if [ -f /root/flags/pt/pt.flag ]; then
        rm -rf /root/flags/pt/pt.flag
    fi

    if [ -f /root/flags/ssrf/ssrf.flag ]; then
        rm -rf /root/flags/ssrf/ssrf.flag
    fi

    if [ -f /root/flags/rce/rce.flag ]; then
        rm -rf /root/flags/rce/rce.flag
    fi

    if [ -f /root/flags/lpe/lpe.flag ]; then
        rm -rf /root/flags/lpe/lpe.flag
    fi

    if [ -f /etc/ue-service ]; then
        rm -rf /etc/ue-service
    fi

    if [ -f /tmp/stf-malware ]; then
        rm -rf /tmp/stf-malware
    fi

    if [ -f /root/ue-service.yaml ]; then
        rm -rf /root/ue-service.yaml
    fi

    if [ -d /root/flags ]; then
        rm -rf /root/flags
    fi


    # OLD FLAGS

    if [ -f /root/ssrf.flag ]; then
        rm -rf /root/ssrf.flag
    fi

    if [ -f /root/rce.flag ]; then
        rm -rf /root/rce.flag
    fi

    if [ -f /home/serve.py ]; then
        rm -rf /home/serve.py
    fi

    if [ -f /home/serv.py ]; then
        rm -rf /home/serv.py
    fi

    if [ -f /etc/systemd/system/ssrftoken.service ]; then
        systemctl stop ssrftoken.service
        systemctl disable ssrftoken.service
        rm -rf /etc/systemd/system/ssrftoken.service
    fi


    echo "[v] Cleanup finished"
}


VALID_ARGS=$(getopt -o qsrplchU:PD:E:H:P:C --long noSQL,noSSRF,noRCE,noLPE,noPT,check,help,user:,password,database:,engine:,host:,port:,cleanup,unacceptable-event,unacceptable-event-path: --name 'auto_rollout.sh' -- "$@")
if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi
eval set -- "$VALID_ARGS"

while true; do
    case "$1" in
        -q | --noSQL )  NO_SQL="true"; shift ;;
        -s | --noSSRF ) NO_SSRF="true"; shift ;;
        -r | --noRCE )  NO_RCE="true"; shift ;;
        -l | --noLPE )  NO_LPE="true"; shift ;;
        -p | --noPT )   NO_PT="true"; shift ;;
        -c | --check )  ONLY_CHECK="true"; shift ;;
        -h | --help )   help; shift ;;
        -U | --user )   db_user="$2"; shift 2 ;;
        -P | --password ) prompt_password; shift ;;
        -D | --database ) db_name="$2"; shift 2 ;;
        -E | --engine ) db_engine="$2"; shift 2 ;;
        -H | --host ) db_host="$2"; shift 2 ;;
        -P | --port ) db_port="$2"; shift 2 ;;
        -C | --cleanup ) cleanup; exit ;;
        --unacceptable-event ) NO_UE="false"; shift ;;
        --unacceptable-event-path ) default_ue_path="$2"; shift 2 ;;
        -- ) shift; break ;;
    esac
done



function print_header {
    echo "---------------------------------"
    echo "Auto rollout flags script v1.0"
    echo " by rozetkin"
    echo "---------------------------------"
}



#bash - define function to check if script is running as root
function check_root {
    if [ "$EUID" -ne 0 ]; then
        echo "[!] Please run as root"
        exit
    fi
}


# check if systemd is installed
function check_systemd {
    if ! [ -x "$(command -v systemctl)" ]; then
        echo "[!] systemd is not installed"
        exit
    fi
}

# check if sudo is installed
function check_sudo {
    if ! [ -x "$(command -v sudo)" ]; then
        # try to install sudo
        apt-get update
        apt-get install sudo -y

        # check if sudo is installed
        if ! [ -x "$(command -v sudo)" ]; then
            echo "[!] sudo is not installed"
            exit
        fi
    fi
}

# check if curl is installed
function check_curl {
    if ! [ -x "$(command -v curl)" ]; then
        # try to install curl
        apt-get update
        apt-get install curl -y

        # check if curl is installed
        if ! [ -x "$(command -v curl)" ]; then
            echo "[!] curl is not installed"
            exit
        fi
    fi
}

# check if we are not in /root
function check_pwd {
    if [ "$PWD" == "/root" ]; then
        echo "[!] Please run this script not in /root"
        exit
    fi
}



# First checks:


# check_root
check_systemd
check_sudo
check_pwd
check_curl


# Integrity check


function integriry_check {
    local conter=0
    # check if all files are in place
    if [ ! -f ./ssrf_server ] && [ "$NO_SSRF" == "false" ]; then
        echo "[!] ssrf_server is not in place"
        counter=$((counter+1))
    fi

    if [ ! -f ./ssrf.service ] && [ "$NO_SSRF" == "false" ]; then
        echo "[!] ssrf.service is not in place"
        counter=$((counter+1))
    fi

    if [ ! -f ./rceflag ] && [ "$NO_RCE" == "false" ]; then
        echo "[!] rceflag is not in place"
        counter=$((counter+1))
    fi

    if [ ! -f ./lpeflag ] && [ "$NO_LPE" == "false" ]; then
        echo "[!] lpeflag is not in place"
        counter=$((counter+1))
    fi

    if [ ! -f ./ue-service ] && [ "$NO_UE" == "false" ]; then
        echo "[!] ue-service is not in place"
        counter=$((counter+1))
    fi

    if [ ! -f ./ue-service.yaml_dummy ] && [ "$NO_UE" == "false" ]; then
        echo "[?] ue-service.yaml_dummy is not in place, creating new one"
        printf "conf:\n\tsha256: <SHA256_HASH>\n\tmd5: <MD5_HASH>\n\tbinaryPath: <BINARY_PATH>\n" > ./ue-service.yaml_dummy
    fi

    if [ ! -f ./ue-malware ] && [ "$NO_UE" == "false" ]; then
        echo "[!] ue-malware is not in place"
        counter=$((counter+1))
    fi

    return $counter
}

integriry_check
is_integrity_check_failed=$?
if [ $is_integrity_check_failed -gt 0 ]; then
    echo "[!] Integrity check failed. Please check if all files are in place"
    exit
fi




# Detect Database engine
# ----------------------

db_engines=()

function detect_engines {
    echo "--- Detecting database engines ---"

    if [ -x "$(command -v mariadb)" ]; then
        echo "[v] mariadb is installed"
        db_engines+=("mariadb")
    else
        # check if mysql is installed
        if [ -x "$(command -v mysql)" ]; then
            echo "[v] mysql is installed"
            db_engines+=("mysql")
        fi
    fi

    # check if postgresql is installed
    if [ -x "$(command -v psql)" ]; then
        echo "[v] postgresql is installed"
        db_engines+=("postgresql")
    fi

    
}


function prompt_database_engine {
    echo "--- Choose database engine ---"
    for (( i=0; i<${#db_engines[@]}; i++ )); do
        echo "[$i] ${db_engines[$i]}"
    done

    echo -n "Enter database engine number: "
    read db_engine

    if [ $db_engine -lt 0 ] || [ $db_engine -ge ${#db_engines[@]} ]; then
        echo "[!] Wrong database engine"
        db_engine=""
    else
        echo "[v] ${db_engines[$db_engine]} is chosen"
        db_engine=${db_engines[$db_engine]}
    fi
}

function prompt_database_name {
    echo -n "Enter database name: "
    read db_name
}

function prompt_database_user {
    echo -n "Enter database user: "
    read db_user
}

function prompt_database_password {
    echo -n "Enter database password: "
    read db_pass
}

function determine_engines {
    if [ "$NO_SQL" == "false" ] && [ "$db_engine" == "" ]; then
        detect_engines
    else
        if [ "$db_engine" != "" ]; then
            db_engines+=("$db_engine")
        else
            echo "[o] No database engine is chosen"
        fi
    fi

    # if no database engine is installed or passed -NoSQL to arguments - skip sql flag rollout
    if  [ ${#db_engines[@]} -eq 0 ]; then
        echo "[o] No database engine is installed"
        echo "[!] No sql flag will be rolled out/checked"
        db_engine=""
        db_name=""
        db_user=""
        db_pass=""
    else
        # if there is only one database engine - choose it
        if [ ${#db_engines[@]} -eq 1 ]; then
            echo "[o] Only one database engine is installed - ${db_engines[0]} is chosen"
            db_engine=${db_engines[0]}
        else
            prompt_database_engine
        fi

        if [ "$db_engine" != "" ]; then

            if [ "$db_name" == "" ]; then
                prompt_database_name
            fi

            if [ "$db_user" == "" ]; then
                prompt_database_user
            fi

            if [ "$db_pass" == "" ]; then
                prompt_database_password
            fi

            # if user is null or password is null - do not pass them to connect string

            db_mysql_connect_string="-h $db_host "
            if [ "$db_port" != "" ]; then
                db_mysql_connect_string+="-P $db_port "
            fi

            if [ "$db_user" == "" ] || [ "$db_pass" == "" ]; then
                db_user="root"
                db_mysql_connect_string+="$db_name "
            else
                db_mysql_connect_string+="-u $db_user -p$db_pass $db_name "
            fi

            

            db_psql_connect_string="-h $db_host "

            if [ "$db_port" != "" ]; then
                db_psql_connect_string+="-p $db_port "
            fi

            if [ "$db_user" == "" ] || [ "$db_pass" == "" ]; then
                db_psql_connect_string+="$db_name "
            else
                db_psql_connect_string+="-U $db_user -d $db_name "
            fi
        fi
    fi

} 


# Prepare environment
# -------------------

# create all necessary directories if not exists

function prepare_enviroment {
    if [ ! -d /root/flags ]; then
        mkdir /root/flags
    fi

    if [ ! -d /root/flags/ssrf ] && [ "$NO_SSRF" == "false" ]; then
        mkdir /root/flags/ssrf
    fi

    if [ ! -d /root/flags/rce ] && [ $NO_RCE == "false" ]; then
        mkdir /root/flags/rce
    fi

    if [ ! -d /root/flags/lpe ] && [ $NO_LPE == "false" ]; then
        mkdir /root/flags/lpe
    fi

    if [ ! -d /root/flags/pt ] && [ $NO_PT == "false" ]; then
        mkdir /root/flags/pt
    fi

    if [ ! -d /root/flags/ue ] && [ $NO_UE == "false" ]; then
        mkdir /root/flags/ue
    fi
}


# SQLinj flag rollout
# -------------------

# if database engine is chosen - roll out sql flag
function sqli_rollout {    
    echo "--- SQLinj flag rollout ---"
    if [ "$db_engine" != "" ]; then
        if [ "$db_engine" == "postgresql" ]; then
            echo "[o] Postgresql database is chosen"

            # try to connect to database with provided credentials
            db_connect=$(PGPASSWORD=$db_pass psql $db_psql_connect_string -c "SELECT 1" 2>/dev/null | grep -w 1 | wc -l)
            if [ $db_connect -eq 0 ]; then
                echo "[!] Cannot connect to postgresql database $db_name with user $db_user"
                exit
            fi

            # drop table if exists
            db_drop_table=$(PGPASSWORD=$db_pass psql $db_psql_connect_string -c "DROP TABLE IF EXISTS secret;" 2>/dev/null | grep "DROP TABLE" | wc -l)
            if [ $db_drop_table -eq 0 ]; then
                echo "[!] Cannot drop table in postgresql database $db_name with user $db_user"
                exit
            fi

            # create table if not exists
            db_create_table=$(PGPASSWORD=$db_pass psql $db_psql_connect_string -c "CREATE TABLE IF NOT EXISTS secret(id SERIAL PRIMARY KEY, flag CHAR(256) NOT NULL);" 2>/dev/null | grep "CREATE TABLE" | wc -l)
            if [ $db_create_table -eq 0 ]; then
                echo "[!] Cannot create table in postgresql database $db_name with user $db_user"
                exit
            fi

            # insert flag into table
            db_insert_flag=$(PGPASSWORD=$db_pass psql $db_psql_connect_string -c "INSERT INTO secret (flag) values ('random_sqli_flag');" 2>/dev/null | grep "INSERT 0 1" | wc -l)

            if [ $db_insert_flag -eq 0 ]; then
                echo "[!] Cannot insert flag into postgresql database $db_name with user $db_user"
                exit
            fi

        elif [ "$db_engine" == "mysql" ] || [ "$db_engine" == "mariadb" ]; then
            if [ "$db_engine" == "mysql" ]; then
                echo "[o] Mysql database is chosen"
            else
                echo "[o] Mariadb (mysql) database is chosen"
            fi
            
            #try to connect to database with provided credentials
            db_connect=$(mysql $db_mysql_connect_string -e "SELECT 1" 2>/dev/null | grep -w 1 | wc -l)
            if [ $db_connect -eq 0 ]; then
                echo "[!] Cannot connect to mysql database '$db_name' with user '$db_user'"
                exit
            fi


            # Drop table if exists
            # echo "DEBUG: mysql $db_mysql_connect_string -e \"DROP TABLE IF EXISTS secret;\""
            db_drop_table=$(mysql $db_mysql_connect_string -e "DROP TABLE IF EXISTS secret;" 2>&1 | grep "ERROR" | wc -l)
            if [ $db_drop_table -eq 1 ]; then
                echo "[!] Cannot drop table in mysql database '$db_name' with user '$db_user'"
                exit
            fi
            
            # create table if not exists (if returns error - fail)
            # echo "DEBUG: mysql $db_mysql_connect_string -e \"CREATE TABLE IF NOT EXISTS secret (id int(11) AUTO_INCREMENT, flag varchar(256) DEFAULT NULL, PRIMARY KEY (id));\""
            db_create_table=$(mysql $db_mysql_connect_string -e "CREATE TABLE IF NOT EXISTS secret (id int(11) AUTO_INCREMENT, flag varchar(256) DEFAULT NULL, PRIMARY KEY (id));" 2>&1 | grep "ERROR" | wc -l)
            if [ $db_create_table -eq 1 ]; then
                echo "[!] Cannot create table in mysql database '$db_name' with user '$db_user'"
                exit
            fi

            # insert flag into table
            # echo "DEBUG: mysql $db_mysql_connect_string -e \"INSERT INTO secret (flag) values ('random_sqli_flag');\""
            db_insert_flag=$(mysql $db_mysql_connect_string -e "INSERT INTO secret (flag) values ('random_sqli_flag');" 2>&1 | grep "ERROR" | wc -l)

            if [ $db_insert_flag -eq 1 ]; then
                echo "[!] Cannot insert flag into mysql database '$db_name' with user '$db_user'"
                exit
            fi

        fi
        echo "[v] Sql flag rollout finished"
    else
        echo "[o] No database engine is chosen, sql flag will not be rolled out"
    fi
}


# SSRF flag rollout
# -----------------
function ssrf_rollout {
    echo "--- SSRF flag rollout ---"

    # flag file
    if [ ! -f /root/flags/ssrf/ssrf.flag ]; then
        echo "random_ssrf_flag" > /root/flags/ssrf/ssrf.flag
    fi
    chmod 0600 /root/flags/ssrf/ssrf.flag

    # ssrf server
    \cp -fR ./ssrf_server /root/ssrf_server
    chmod 0500 /root/ssrf_server

    # ssrf service
    \cp -fR ./ssrf.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl start ssrf.service
    systemctl enable ssrf.service
    echo "[v] Ssrf flag rollout finished"

}

# RCE flag rollout
# ----------------
function rce_rollout {
    echo "--- RCE flag rollout ---"

    # flag file
    if [ ! -f /root/flags/rce/rce.flag ]; then
        echo "random_rce_flag" > /root/flags/rce/rce.flag
    fi
    chmod 0600 /root/flags/rce/rce.flag

    # binary
    \cp -fR ./rceflag /home/rceflag
    chmod 4755 /home/rceflag
    echo "[v] Rce flag rollout finished"
}

# LPE flag rollout
# ----------------
function lpe_rollout {
    echo "--- LPE flag rollout ---"

    # flag file
    if [ ! -f /root/flags/lpe/lpe.flag ]; then
        echo "random_lpe_flag" > /root/flags/lpe/lpe.flag
    fi
    chmod 0600 /root/flags/lpe/lpe.flag

    # binary
    \cp -fR ./lpeflag /home/lpeflag
    chmod 0755 /home/lpeflag
    echo "[v] Lpe flag rollout finished"
}


# Path Traversal flag rollout  
# ---------------------------
function pt_rollout {
    echo "--- Path Traversal flag rollout ---"

    # flag file
    if [ ! -f /root/flags/pt/pt.flag ]; then
        echo "random_pt_flag" > /root/flags/pt/pt.flag
    fi

    chmod 0644 /root/flags/pt/pt.flag

    # symlink
    ln -f /root/flags/pt/pt.flag /etc/pt.flag
    echo "[v] Path traversal flag rollout finished"
}


# Unacceptable event flag rollout
# -------------------------------
function ue_rollout {
    echo "--- Unacceptable event flag rollout ---"

    # flag file
    if [ ! -f /root/flags/ue/ue.flag ]; then
        echo "random_ue_flag" > /root/flags/ue/ue.flag
    fi

    chmod 0644 /root/flags/ue/ue.flag

    # binary
    \cp -fR ./ue-service /etc/ue-service
    chmod 4755 /etc/ue-service

    # config
    \cp -fR ./ue-service.yaml_dummy /root/ue-service.yaml
    chmod 0600 /root/ue-service.yaml

    # calculate md5sum of malware
    malware_md5=$(md5sum ./ue-malware | awk '{print $1}')

    # calculate sha256sum of malware
    malware_sha256=$(sha256sum ./ue-malware | awk '{print $1}')

    # replace md5sum and sha256sum in config
    sed -i "s|<MD5_HASH>|$malware_md5|g" /root/ue-service.yaml
    sed -i "s|<SHA256_HASH>|$malware_sha256|g" /root/ue-service.yaml

    # replace path to malware in config
    sed -i "s|<BINARY_PATH>|$default_ue_path|g" /root/ue-service.yaml
    
    echo "[v] Unacceptable event flag rollout finished"
}


# Check if all flags are in place
# -------------------------------
# SQLinj flag - check if database returns the flag if requested
# SSRF flag - check if ssrf_server is running and returns the flag if requested to localhost:9732
# RCE flag - check if /home/rceflag is in place and executing it returns the flag
# LPE flag - check if /home/lpeflag is in place and executing it returns the flag
# Path Traversal flag - check if /root/flags/pt/pt.flag is in place and reading /etc/pt.flag returns the flag

# SQLinj flag check
# -----------------

function sqli_check {
    echo "--- SQLinj flag check ---"

    if [ "$db_engine" == "" ]; then
        echo "[o] No sqli flag is rolled out"
    elif [ "$db_engine" == "postgresql" ]; then

        # check connection to database
        db_connect=$(PGPASSWORD=$db_pass psql $db_psql_connect_string -c "SELECT 1" 2>/dev/null | grep -w 1 | wc -l)
        if [ $db_connect -eq 0 ]; then
            echo "[!] Cannot connect to postgresql database '$db_name' with user '$db_user'"
            return
        fi

        # request flag from database
        db_flag_res=$(PGPASSWORD=$db_pass psql $db_psql_connect_string -c "SELECT flag FROM secret where id = 1;" 2>/dev/null )


        # parse flag from result
        db_flag_res_default=$(echo $db_flag_res | grep -o -E "random_sqli_flag")
        db_flag_res_flag=$(echo $db_flag_res | grep -o -E "[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}")

        db_default_flag=$(echo $db_flag_res_default | wc -l) # check if default flag is in place
        db_flag=$(echo $db_flag_res | wc -l)

        if [[ $db_default_flag -eq 1 ]]; then
            echo "[v] Postgresql database returns default the flag"
        else
            if [ $db_flag -eq 1 ]; then
                echo "[v] Postgresql database returns the flag"
                echo "[?] Returned: $db_flag_res_flag"
            else
                echo "[!] Postgresql database does not return the flag"
                printf "[?] Returned: $db_flag_res\n"
            fi
        fi  
    elif [ "$db_engine" == "mysql" ] || [ "$db_engine" == "mariadb" ]; then

        # try to connect to database with provided credentials
        db_connect=$(mysql $db_mysql_connect_string -e "SELECT 1" 2>/dev/null | grep -w 1 | wc -l)
        if [ $db_connect -eq 0 ]; then
            echo "[!] Cannot connect to mysql database '$db_name' with user '$db_user'"
            return
        fi

        # request flag from database
        # echo "DEBUG: mysql $db_mysql_connect_string -e \"SELECT flag FROM secret;\""
        db_flag_res=$(mysql $db_mysql_connect_string -e "SELECT flag FROM secret where id = 1;" 2>/dev/null )


        # parse flag from result
        db_flag_res_default=$(echo $db_flag_res | grep -o -E "random_sqli_flag")
        db_flag_res_flag=$(echo $db_flag_res | grep -o -E "[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}")



        db_default_flag=$(echo $db_flag_res_default | wc -l) # check if default flag is in place
        db_flag=$(echo $db_flag_res_flag | wc -l) # check if flag is in place
        

        #check if db_flag_res is empty
        if [ -z "$db_flag_res" ]; then
            echo "[!] Cannot connect to mysql database '$db_name' with user '$db_user'"
            return
        fi
        

        if [[ $db_default_flag -eq 1 ]]; then
            echo "[v] Mysql database returns default the flag"
        else
            if [ $db_flag -eq 1 ]; then
                echo "[v] Mysql database returns the flag"
                echo "[?] Returned: $db_flag_res_flag"
            else
                echo "[!] Mysql database does not return the flag"
                printf "[?] Returned: $db_flag_res\n"
            fi
        fi
    fi
}


# SSRF flag check
# ---------------

function ssrf_check {
    echo "--- SSRF flag check ---"
    # check if ssrf_server is running
    ssrf_server_status=$(systemctl status ssrf.service | grep "Active: active (running)" | wc -l)
    if [ $ssrf_server_status -eq 1 ]; then
        echo "[v] ssrf_server is running"
    else
        echo "[!] ssrf_server is not running"
    fi

    # check if /root/flags/ssrf/ssrf.flag is in place
    if [ -f /root/flags/ssrf/ssrf.flag ]; then
        echo "[v] /root/flags/ssrf/ssrf.flag is in place"
    else
        echo "[!] /root/flags/ssrf/ssrf.flag is not in place"
        return
    fi

    # read value from /root/flags/ssrf/ssrf.flag
    expected_ssrf_flag=$(cat /root/flags/ssrf/ssrf.flag)

    # check if ssrf_server returns the flag
    ssrf_flag=$(curl -s http://localhost:9732/)
    if [ "$ssrf_flag" == "random_ssrf_flag" ]; then
        echo "[v] ssrf_server returns the default flag"
    else
        if [ "$ssrf_flag" == "$expected_ssrf_flag" ]; then
            echo "[v] ssrf_server returns the flag"
            echo "[?] Returned: $ssrf_flag"
        else
            echo "[!] ssrf_server does not return the flag"
            echo "[?] Returned: $ssrf_flag"
        fi
    fi
}

# RCE flag check
# --------------

function rce_check {
echo "--- RCE flag check ---"
    # check if /home/rceflag is in place
    if [ -f /home/rceflag ]; then
        echo "[v] /home/rceflag is in place"
    else
        echo "[!] /home/rceflag is not in place"
    fi

    # check if /root/flags/rce/rce.flag is in place
    if [ -f /root/flags/rce/rce.flag ]; then
        echo "[v] /root/flags/rce/rce.flag is in place"
    else
        echo "[!] /root/flags/rce/rce.flag is not in place"
        return
    fi

    # read flag from /root/flags/rce/rce.flag
    expected_rce_flag=$(cat /root/flags/rce/rce.flag)

    # check if /home/rceflag returns the flag when executed not as root
    rce_flag=$(sudo -u nobody /home/rceflag)
    if [[ "$rce_flag" == *"random_rce_flag"* ]]; then
        echo "[v] /home/rceflag returns the default flag"
    else
        if [ "$rce_flag" == "$expected_rce_flag" ]; then
            echo "[v] /home/rceflag returns the flag"
            echo "[?] Returned: $rce_flag"
        else
            echo "[!] /home/rceflag does not return the flag"
            echo "[?] Returned: $rce_flag"
        fi
    fi
}
# LPE flag check
# --------------

function lpe_check {
    echo "--- LPE flag check ---"

    # check if /home/lpeflag is in place
    if [ -f /home/lpeflag ]; then
        echo "[v] /home/lpeflag is in place"
    else
        echo "[!] /home/lpeflag is not in place"
    fi

    # check if /root/flags/lpe/lpe.flag is in place
    if [ -f /root/flags/lpe/lpe.flag ]; then
        echo "[v] /root/flags/lpe/lpe.flag is in place"
    else
        echo "[!] /root/flags/lpe/lpe.flag is not in place"
        return
    fi

    # read flag from /root/flags/lpe/lpe.flag
    expected_lpe_flag=$(cat /root/flags/lpe/lpe.flag)

    # check if /home/lpeflag not returns the flag when executed not as root
    lpe_flag=$(sudo -u nobody /home/lpeflag 2>/dev/null)
    if [ "$lpe_flag" == "random_lpe_flag" ]; then
        echo "[!] /home/lpeflag returns the default flag when executed not as root"
    else
        if [ "$lpe_flag" == "$expected_lpe_flag" ]; then
            echo "[!] /home/lpeflag returns the flag when executed not as root"
            echo "[?] Returned: $lpe_flag"
        else
            echo "[v] /home/lpeflag does not return the flag when executed not as root"
        fi
    fi

    # check if /home/lpeflag returns the flag when executed as root (silent for errors)
    lpe_flag=$(sudo /home/lpeflag 2>/dev/null)
    if [ "$lpe_flag" == "random_lpe_flag" ]; then
        echo "[v] /home/lpeflag returns the default flag when executed as root"
    else
        if [ "$lpe_flag" == "$expected_lpe_flag" ]; then
            echo "[v] /home/lpeflag returns the flag when executed as root"
            echo "[?] Returned: $lpe_flag"
        else
            echo "[!] /home/lpeflag does not return the flag when executed as root"
            echo "[?] Returned: $lpe_flag"
        fi
    fi
}

# Path Traversal flag check
# -------------------------

function pt_check {
    echo "--- Path Traversal flag check ---"

    # check if /etc/pt.flag is in place
    if [ -f /etc/pt.flag ]; then
        echo "[v] /etc/pt.flag is in place"
    else
        echo "[!] /etc/pt.flag is not in place"
    fi

    # check if /root/flags/pt/pt.flag is in place
    if [ -f /root/flags/pt/pt.flag ]; then
        echo "[v] /root/flags/pt/pt.flag is in place"
    else
        echo "[!] /root/flags/pt/pt.flag is not in place"
        return
    fi

    # read flag from /root/flags/pt/pt.flag
    expected_pt_flag=$(cat /root/flags/pt/pt.flag)

    # check if /etc/pt.flag returns the flag when read as nobody (silent for errors)
    pt_flag=$(sudo -u nobody cat /etc/pt.flag 2>/dev/null)
    if [ "$pt_flag" == "random_pt_flag" ]; then
        echo "[v] /etc/pt.flag returns the default flag when read as nobody"
    else
        if [ "$pt_flag" == "$expected_pt_flag" ]; then
            echo "[v] /etc/pt.flag returns the flag when read as nobody"
            echo "[?] Returned: $pt_flag"
        else
            echo "[!] /etc/pt.flag does not return the flag when read as nobody"
            echo "[?] Returned: $pt_flag"
        fi
    fi
}

# Unacceptable event flag check
# -----------------------------


# config example:
# conf:
#     sha256: <SHA256_HASH>
#     md5: <MD5_HASH>
#     binaryPath: <BINARY_PATH>



function ue_check {
    echo "--- Unacceptable event flag check ---"

    # check if /root/flags/ue/ue.flag is in place
    if [ -f /root/flags/ue/ue.flag ]; then
        echo "[v] /root/flags/ue/ue.flag is in place"
    else
        echo "[!] /root/flags/ue/ue.flag is not in place"
        return
    fi

    # check for config  
    if [ -f /root/ue-service.yaml ]; then
        echo "[v] /root/ue-service.yaml is in place"
    else
        echo "[!] /root/ue-service.yaml is not in place"
        return
    fi

    # read sha256sum from /root/ue-service.yaml
    expected_ue_sha256=$(cat /root/ue-service.yaml | grep "sha256" | awk '{print $2}')

    # read md5sum from /root/ue-service.yaml
    expected_ue_md5=$(cat /root/ue-service.yaml | grep "md5" | awk '{print $2}')

    # read path from /root/ue-service.yaml
    expected_ue_path=$(cat /root/ue-service.yaml | grep "binaryPath" | awk '{print $2}')



    # read flag from /root/flags/ue/ue.flag
    expected_ue_flag=$(cat /root/flags/ue/ue.flag)


    # check md5sum of malware
    malware_md5=$(md5sum ./ue-malware | awk '{print $1}')
    malware_sha256=$(sha256sum ./ue-malware | awk '{print $1}')

    if [ "$malware_md5" != "$expected_ue_md5" ]; then
        echo "[!] MD5 hash of provided malware does not match"
        echo "[?] Expected: $expected_ue_md5"
        echo "[?] Returned: $malware_md5"
    else
        echo "[v] MD5 hash of malware matches"
    fi

    if [ "$malware_sha256" != "$expected_ue_sha256" ]; then
        echo "[!] SHA256 hash of provided malware does not match"
        echo "[?] Expected: $expected_ue_sha256"
        echo "[?] Returned: $malware_sha256"
    else
        echo "[v] SHA256 hash of malware matches"
    fi

    # copy malware to expected path
    \cp -fR ./ue-malware $expected_ue_path

    # set permissions
    chmod 755 $expected_ue_path

    # check if malware returns the flag when executed as nobody (silent for errors)
    ue_flag=$(sudo -u nobody $expected_ue_path -s 2>/dev/null)

    # check if substring is in returned value
    if [[ "$ue_flag" == *"random_ue_flag"* ]]; then
        echo "[v] $expected_ue_path returns the default flag when executed as nobody"
    else
        if [[ "$ue_flag" == *"$expected_ue_flag"* ]]; then
            echo "[v] $expected_ue_path returns the flag when executed as nobody"
            echo "[?] Returned: $ue_flag"
        else
            echo "[!] $expected_ue_path does not return the flag when executed as nobody"
            echo "[?] Returned: $ue_flag"
        fi
    fi

    # remove malware from expected path
    rm -rf $expected_ue_path
}






# Main part
print_header

determine_engines

if [ "$ONLY_CHECK" == "true" ]; then
    sqli_check
    ssrf_check
    rce_check
    lpe_check
    pt_check
    ue_check
else
    # Prepare environment
    prepare_enviroment

    # Rollout
    if [ "$NO_SQL" == "false" ]; then
        sqli_rollout
    fi

    if [ "$NO_SSRF" == "false" ]; then
        ssrf_rollout
    fi

    if [ "$NO_RCE" == "false" ]; then
        rce_rollout
    fi

    if [ "$NO_LPE" == "false" ]; then
        lpe_rollout
    fi

    if [ "$NO_PT" == "false" ]; then
        pt_rollout
    fi

    if [ "$NO_UE" == "false" ]; then
        ue_rollout
    fi

    # Checks
    if [ "$NO_SQL" == "false" ]; then
        sqli_check
    fi

    if [ "$NO_SSRF" == "false" ]; then
        ssrf_check
    fi

    if [ "$NO_RCE" == "false" ]; then
        rce_check
    fi

    if [ "$NO_LPE" == "false" ]; then
        lpe_check
    fi

    if [ "$NO_PT" == "false" ]; then
        pt_check
    fi

    if [ "$NO_UE" == "false" ]; then
        ue_check
    fi
fi