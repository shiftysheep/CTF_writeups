#!/bin/ash

# change flag name
mv /flag.txt /flag$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 10).txt

# Secure entrypoint
chmod 600 /entrypoint.sh

# Initialize & Start MariaDB
mkdir -p /run/mysqld
chown -R mysql:mysql /run/mysqld
mysql_install_db --user=mysql --ldata=/var/lib/mysql
mysqld --user=mysql --console --skip-networking=0 &

# Wait for mysql to start
while ! mysqladmin ping -h'localhost' --silent; do echo 'not up' && sleep .2; done

function genPass() {
    echo -n $RANDOM | md5sum | head -c 32
}

mysql -u root << EOF
CREATE DATABASE web_desynth_recruit;
CREATE TABLE web_desynth_recruit.users (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    username varchar(255) NOT NULL UNIQUE,
    password varchar(255) NOT NULL,
    full_name varchar(255) DEFAULT '',
    issn  varchar(255) DEFAULT '',
    qualification  varchar(255) DEFAULT '',
    bio varchar(255) DEFAULT '',
    iexp varchar(255) DEFAULT '',
    meta_desc varchar(255) DEFAULT '',
    is_public varchar(255) DEFAULT '',
    meta_keywords varchar(255) DEFAULT '',
    bots varchar(255) DEFAULT '',
    ipc_submitted varchar(255) DEFAULT '0',
    ipc_verified varchar(255) DEFAULT '0'
);

INSERT INTO web_desynth_recruit.users(
    id,
    username, 
    password, 
    full_name, 
    issn, 
    qualification, 
    bio, 
    iexp, 
    meta_desc, 
    is_public, 
    meta_keywords, 
    bots, 
    ipc_submitted, 
    ipc_verified
    ) VALUES(
        1,
        'admin', 
        '$(genPass)', 
        'Pete Maverick', 
        '1333333333333337', 
        'BPC','I\'m very passionate about bot piloting and I have set myself on a long term goal of training the next generation of bot pilots.','8', 'Pete Maverick\'s Profile', '1', 'expert, veteran, master-pilot, trainer', 
        '["DisBot", "FBot", "GoBot", "InstaBot", "RedBot", "SpotBot", "TicBot", "TwiBot","ViBot"]', 
        '1', 
        '1'
    );

INSERT INTO web_desynth_recruit.users(
    username, 
    password, 
    full_name, 
    issn, 
    qualification, 
    bio, 
    iexp, 
    meta_desc, 
    is_public, 
    meta_keywords, 
    bots, 
    ipc_submitted, 
    ipc_verified
    ) VALUES(
        'reidB', 
        '$(genPass)', 
        'Reid Belmont', 
        '4358942134574267', 
        'HPC',
        'Young Pilot professional with good track record in modern bots.',
        '4', 
        'Reid Belmont | HPC', 
        '1', 
        'young, skilled, hpc-pilot', 
        '["DisBot", "FBot", "GoBot", "InstaBot"]', 
        '1', 
        '1'
    );

CREATE USER 'user'@'localhost' IDENTIFIED BY 'xClow3n123';
GRANT SELECT, INSERT, UPDATE ON web_desynth_recruit.users TO 'user'@'localhost';
FLUSH PRIVILEGES;
EOF

/usr/bin/supervisord -c /etc/supervisord.conf