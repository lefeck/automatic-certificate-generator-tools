#!/bin/bash
#
set -Eeuo pipefail

trap 'die "💥 Something went wrong." ' ERR
trap 'exit 0' EXIT

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd -P)
# check whether the date command-line tools exists
[[ ! -x "$(command -v date)" ]] && echo "💥 date command not found." && exit 1

function log() {
    echo >&2 -e "[$(date +"%Y-%m-%d %H:%M:%S")] ${1-}"
}

function die() {
    local msg=$1
    local code=${2-1}
    log "$msg"
    exit "$code"
}

function usage() {
    cat << EOF

Usage: $(basename "${BASH_SOURCE[0]}") [-a [rsa|ecc]] [-d <domain>] [-n <name>] [-t <days>] [-p <password>] [-s <show>] [-l <length>] [-C <country>] [-S <state>]  [-L <local>] [-O <organization>] [-o <organizational_unit>]  [-N <common_name>] [-h] [-v]

💁 This script will automatically generate certificates.

Available options:

-a --algorithm         Algorithms supported by the issuing certificate tool. for example: rsa, ecc, default the algorithm is "rsa".
-d --domain-name       The name of the domain for which the certificate is issued. for example: xxx.com, abc.org, *.abc.org, default is "domain.com".
-t --days              Set the expiration time of the certificate, default is 3650 days.
-p --password          Set password for the service certificate, default is a random string.
-s --show              Whether to display the service certificate password in the foreground. By default, it will write to a .password file.
-l --length            Set the length of the password, default is 8 characters. This parameter and the -p option cannot be used together.
-C --country           Set the country for the certificate, default is "CN".
-S --state             Set the state for the certificate, default is "ShangHai".
-L --local             Set the locality for the certificate, default is "ShangHai".
-O --organization      Set the organization for the certificate, default is "MY".
-o --organizational-unit Set the organizational unit for the certificate, default is "IT Department".
-N --common-name       Set the common name for the certificate, default is "MY CA".
-h --help              Print this help and exit.
-v --verbose           Print script debug info.
EOF
    exit 0
}

function generate_random_pwd() {
    length=${length:-8}
    local seq=(0 1 2 3 4 5 6 7 8 9 a b c d e f g h i j k l m n o p q r s t u v w x y z A B C D E F G H I J K L M N O P Q R S T U V W X Y Z)
    local num_seq=${#seq[@]}
    local random_str=""

    for ((i=0; i<length; i++)); do
        random_str+="${seq[$((RANDOM % num_seq))]}"
    done
    echo "$random_str"
}

function parse_param() {
    length=${length:-8}
    domain_name=${domain_name:-"www.pocdomain.com"}
    algorithm=${algorithm:-""}
    days=${days:-3650}
    show=${show:-"false"}
    certificate_dir=${certificate_dir:-"/tmp/cert"}

    country=${country:-"CN"}
    state=${state:-"ShangHai"}
    local=${local:-"ShangHai"}
    organization=${organization:-"MY"}
    organizational_unit=${organizational_unit:-"IT Department"}
    common_name=${common_name:-"MY CA"}

    getopt_cmd=$(getopt -o a:d:n:t:p:l:C:S:L:O:o:N:shv --long algorithm:,domain:,name:,days:,password:,length:,country:,state:,local:,organization:,organizational-unit:,common-name:,show,help,verbose -n $(basename "$0") -- "$@")

    if [ $? -ne 0 ]; then
        die "💥 Invalid options"
    fi
    eval set -- "$getopt_cmd"
    while true; do
        case "$1" in
            -a | --algorithm) algorithm=$2; shift 2 ;;
            -d | --domain-name) domain_name=$2; shift 2 ;;
            -t | --days) days=$2; shift 2 ;;
            -p | --password) password=$2; shift 2 ;;
            -l | --length) length=$2; shift 2 ;;
            -s | --show) show="true"; shift ;;
            -C | --country) country=$2; shift 2 ;;
            -S | --state) state=$2; shift 2 ;;
            -L | --local) local=$2; shift 2 ;;
            -O | --organization) organization=$2; shift 2 ;;
            -o | --organizational-unit) organizational_unit=$2; shift 2 ;;
            -N | --common-name) common_name=$2; shift 2 ;;
            -h | --help) usage ;;
            -v | --verbose) set -x; shift ;;
            --) shift; break ;;
            *) usage ;;
        esac
    done

    password=${password:-$(generate_random_pwd)}
    log "👶 Starting up..."
}

function generate_certificate_dir() {
    certificate_dir=$(mktemp -d)
    if [[ ! "${certificate_dir}" || ! -d "${certificate_dir}" ]]; then
        die "💥 Could not create temporary working directory."
    else
        log "📁 Created temporary working directory $certificate_dir"
    fi
}

function get_algorithm() {
    if [[ ${algorithm} == "rsa" ]]; then
        rsa_len=2048
    elif [[ ${algorithm} == "ecc" ]]; then
        ecc_name=prime256v1
    else
        usage
    fi
}

function certificate_file_name() {
   # get_algorithm
    generate_certificate_dir
    fqdn=${domain_name}
    ca_key_file="${certificate_dir}/ca.key"
    ca_crt_file="${certificate_dir}/ca.crt"
    srv_key_file="${certificate_dir}/${fqdn}.key"
    srv_csr_file="${certificate_dir}/${fqdn}.csr"
    srv_crt_file="${certificate_dir}/${fqdn}.crt"
    srv_p12_file="${certificate_dir}/${fqdn}.p12"
    srv_pem_file="${certificate_dir}/${fqdn}.pem"
    srv_der_file="${certificate_dir}/${fqdn}.der"
    srv_pfx_file="${certificate_dir}/${fqdn}.pfx"
    srv_fullchain_file="${certificate_dir}/${fqdn}-fullchain.crt"
    v3_extension_file="${certificate_dir}/v3.ext"
}

function create_ca_certificate_and_key() {
    local ca_subj="/C=${country}/ST=${state}/L=${local}/O=${organization}/OU=${organizational_unit}/CN=${domain_name}"
    certificate_file_name
    if [ ! -f "${ca_key_file}" ]; then
        if [[ ${algorithm} == "rsa" ]]; then
            openssl genpkey -algorithm RSA -out ${ca_key_file} -pkeyopt rsa_keygen_bits:${rsa_len} > /dev/null 2>&1
        elif [[ ${algorithm} == "ecc" ]]; then
            openssl ecparam -name ${ecc_name} -genkey -noout -out ${ca_key_file} > /dev/null 2>&1
        else
            openssl genrsa -out ${ca_key_file}  4096 > /dev/null 2>&1
        fi
        log "👍 Generated CA certificate key file"
        openssl req -x509 -new -nodes -sha512 -days ${days} -subj "${ca_subj}" -key ${ca_key_file} -out ${ca_crt_file}
        if [ $? -eq 0 ]; then
            log "👍 Generated CA certificate file"
        else
            die "💥 Failed to generate CA certificate file"
        fi
    fi
}

function certificate_format_convert() {
    cat ${srv_crt_file} ${ca_crt_file} > ${srv_fullchain_file}
    log "👍 Generated server fullchain file"

    openssl pkcs12 -export -inkey ${srv_key_file} -in ${srv_crt_file} -CAfile ${ca_crt_file} -chain -passout pass:${password} -out ${srv_p12_file}
    log "👍 Certificate format converted to P12"

    openssl x509 -in ${srv_crt_file} -out ${srv_pem_file}
    log "👍 Certificate format converted to PEM"

    openssl x509 -outform der -in ${srv_pem_file} -out ${srv_der_file}
    log "👍 Certificate format converted to DER"

    openssl pkcs12 -inkey ${srv_key_file} -in ${srv_crt_file} -export -passout pass:${password} -out ${srv_pfx_file}
    log "👍 Certificate format converted to PFX"

    if [ ${show} == "true" ]; then
        log "👍 The certificate server password is ${password}"
    else
        printf "certificate password: ${password}\n" > "${certificate_dir}/.password"
        log "👍 The certificate password is in ${certificate_dir}/.password file"
    fi

    die "✅ Completed." 0
}

function create_server_certificate_and_key() {
    local server_subj="/C=${country}/ST=${state}/L=${local}/O=${organization}/OU=${organizational_unit}/CN=${domain_name}"
    create_ca_certificate_and_key
    if [ ! -f "${srv_key_file}" ]; then
        if [[ ${algorithm} == "rsa" ]]; then
            openssl genpkey -algorithm RSA -out ${srv_key_file} -pkeyopt rsa_keygen_bits:${rsa_len} > /dev/null 2>&1
        elif [[ ${algorithm} == "ecc" ]]; then
            openssl ecparam -name ${ecc_name} -genkey -noout -out ${srv_key_file} > /dev/null 2>&1
        else
            openssl genrsa -out ${srv_key_file}  4096 > /dev/null 2>&1
        fi
        log "👍 Generated server key file"

        openssl req -new -sha256 -subj "${server_subj}" -key ${srv_key_file} -out ${srv_csr_file}
        log "👍 Generated server CSR (Certificate Signing Request) file"

        log "👍 Generating x509 v3 extension file"
        cat > ${v3_extension_file} <<-EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1=${domain_name}
EOF
        openssl x509 -req -sha256 -days ${days} -extfile ${v3_extension_file} -extensions SAN -CA ${ca_crt_file} -CAkey ${ca_key_file} -CAcreateserial -in ${srv_csr_file} -out ${srv_crt_file} > /dev/null 2>&1
        log "👍 Generated server certificate file"

        certificate_format_convert
    fi
}

function main() {
    parse_param "$@"
    create_server_certificate_and_key
}

main "$@"