#!/usr/bin/env bash

set -e

export LANG=C

kind=server
host=$(hostname -f)
client=client

[ -z "$USER" ] && USER=root

DIR=${TARGET:='.'}
# A space-separated list of alternate hostnames (subjAltName)
# may be empty ""
ALTHOSTNAMES=${HOSTLIST}
ALTADDRESSES=${IPLIST}
CA_ORG='/O=MyCompany.org/OU=generate-CA/emailAddress=nobody@example.net'
CA_CLIENT_ORG='/O=MyCompany.org/emailAddress=nobody@example.net'
CA_DN="/CN=An MQTT broker${CA_ORG}"
CACERT=${DIR}/ca
SERVER="${DIR}/${host}"
SERVER_DN="/CN=${host}$CA_ORG"
CLIENT="${DIR}/${client}"
CLIENT_DN="/CN=${client}$CA_CLIENT_ORG"
keybits=2048
openssl=$(which openssl)
MOSQUITTOUSER=${MOSQUITTOUSER:=$USER}

# Signature Algorithm. To find out which are supported by your
# version of OpenSSL, run `openssl dgst -help` and set your
# signature algorithm here. For example:
#
#	defaultmd="-sha256"
#
defaultmd="-sha512"

function maxdays() {
	nowyear=$(date +%Y)
	years=$(expr 2032 - $nowyear)
	days=$(expr $years '*' 365)

	echo $days
}

function getipaddresses() {
	/sbin/ifconfig |
		grep -v tunnel |
		sed -En '/inet6? /p' |
		sed -Ee 's/inet6? (addr:)?//' |
		awk '{print $1;}' |
		sed -e 's/[%/].*//' |
		egrep -v '(::1|127\.0\.0\.1)'	# omit loopback to add it later
}


function addresslist() {

	ALIST=""
	for a in $(getipaddresses); do
		ALIST="${ALIST}IP:$a,"
	done
	ALIST="${ALIST}IP:127.0.0.1,IP:::1,"

	for ip in $(echo ${ALTADDRESSES}); do
		ALIST="${ALIST}IP:${ip},"
	done
	for h in $(echo ${ALTHOSTNAMES}); do
		ALIST="${ALIST}DNS:$h,"
	done
	ALIST="${ALIST}DNS:localhost"
	echo $ALIST

}

days=$(maxdays)

if [ -n "$CAKILLFILES" ]; then
	rm -f $CACERT.??? $SERVER.??? $CACERT.srl
fi

if [ ! -f $CACERT.crt ]; then

	#    ____    _
	#   / ___|  / \
	#  | |     / _ \
	#  | |___ / ___ \
	#   \____/_/   \_\
	#

	# Create un-encrypted (!) key
	$openssl req -newkey rsa:${keybits} -x509 -nodes $defaultmd -days $days -extensions v3_ca -keyout $CACERT.key -out $CACERT.crt -subj "${CA_DN}"
	echo "Created CA certificate in $CACERT.crt"
	$openssl x509 -in $CACERT.crt -nameopt multiline -subject -noout

	chmod 400 $CACERT.key
	chmod 444 $CACERT.crt
	chown $MOSQUITTOUSER $CACERT.*
	echo "Warning: the CA key is not encrypted; store it safely!"
fi

if [ ! -f $SERVER.key ]; then
	echo "--- Creating server key and signing request"
	$openssl genrsa -out $SERVER.key $keybits
	$openssl req -new $defaultmd \
		-out $SERVER.csr \
		-key $SERVER.key \
		-subj "${SERVER_DN}"
	chmod 400 $SERVER.key
	chown $MOSQUITTOUSER $SERVER.key
fi

if [ -f $SERVER.csr -a ! -f $SERVER.crt ]; then

	# There's no way to pass subjAltName on the CLI so
	# create a cnf file and use that.

	CNF=`mktemp /tmp/cacnf.XXXXXXXX` || { echo "$0: can't create temp file" >&2; exit 1; }
	sed -e 's/^.*%%% //' > $CNF <<\!ENDconfig
	%%% [ JPMextensions ]
	%%% basicConstraints        = critical,CA:false
	%%% nsCertType              = server
	%%% keyUsage                = nonRepudiation, digitalSignature, keyEncipherment
	%%% nsComment               = "Broker Certificate"
	%%% subjectKeyIdentifier    = hash
	%%% authorityKeyIdentifier  = keyid,issuer:always
	%%% subjectAltName          = $ENV::SUBJALTNAME
	%%% certificatePolicies     = ia5org,@polsection
	%%% #
	%%% [polsection]
	%%% policyIdentifier	    = 1.3.5.8
	%%% CPS.1		    = "http://localhost"
	%%% userNotice.1	    = @notice
	%%% #
	%%% [notice]
	%%% explicitText            = "This CA is for a local MQTT broker installation only"
	%%% organization            = "MyCompany"
	%%% noticeNumbers           = 1

!ENDconfig

	SUBJALTNAME="$(addresslist)"
	export SUBJALTNAME		# Use environment. Because I can. ;-)

	echo "--- Creating and signing server certificate"
	$openssl x509 -req $defaultmd \
		-in $SERVER.csr \
		-CA $CACERT.crt \
		-CAkey $CACERT.key \
		-CAcreateserial \
		-CAserial "${DIR}/ca.srl" \
		-out $SERVER.crt \
		-days $days \
		-extfile ${CNF} \
		-extensions JPMextensions

	rm -f $CNF
	chmod 444 $SERVER.crt
	chown $MOSQUITTOUSER $SERVER.crt
fi

if [ ! -f $CACERT.crt ]
then
    echo "ERROR: Could not find CA certificate: $CACERT.crt" >&2
    echo "Exiting..." >&2
    exit 1
fi

if [ ! -f $CLIENT.key ]
then
    echo "--- Creating client key and signing request"
    echo "--- WARNING: key is not encrypted, keep it safe!"
    $openssl genrsa -out $CLIENT.key $keybits
    $openssl req -new \
        -out $CLIENT.csr \
        -key $CLIENT.key \
        -subj "${CLIENT_DN}"
    chmod 400 $CLIENT.key
fi

if [ -f $CLIENT.csr -a ! -f $CLIENT.crt ]
then
    echo "--- Creating and signing client certificate"
    $openssl x509 -req \
        -in $CLIENT.csr \
        -CA $CACERT.crt \
        -CAkey $CACERT.key \
        -CAserial "${DIR}/ca.srl" \
        -out $CLIENT.crt \
        -days $days

    chmod 444 $CLIENT.crt
fi
