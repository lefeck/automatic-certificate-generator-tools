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

# usage of the command line tool
function usage() {
	cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [-a [rsa|ecc]] [-f <domain>] [-t <days>] [-p <password>] [-s <show>] [-l <length>] [-C <country>] [-S <state>]  [-L <local>] [-O <organization>] [-o <organizational_unit>]  [-N <common_name>] [-e <ec_name>] [-r <rsa_key_length>] [-h] [-v]

💁 This script will automatically generate certificates.

Available options:

-a, --algorithm         Algorithms supported by the issuing certificate tool. for example: rsa, ecc, default the algorithm is "rsa".
-f, --fqdn              Set the domain name for the certificate, default is "www.pocdomain.com".
-t, --days              Set the expiration time of the certificate, default is 3650 days.
-p, --password          Set password for the service certificate, default is a random string.
-s, --show              Whether to display the service certificate password in the foreground. By default, it will write to a .password file.
-l, --length            Set the length of the password, default is 8 characters. This parameter and the -p option cannot be used together.
-C, --country           Set the country for the certificate, default is "CN".
-S, --state             Set the state for the certificate, default is "ShangHai".
-L, --local             Set the locality for the certificate, default is "ShangHai".
-O, --organization      Set the organization for the certificate, default is "Personal".
-o, --organizational-unit Set the organizational unit for the certificate, default is "IT Department".
-N, --common-name       Set the common name for the certificate, default is "MY CA".
-e, --ec-name           Specifies the elliptic curve (EC) name for the certificate, such as secp256k1, secp384r1, secp521r1, or prime256v1. The default is secp256k1.
-r, --rsa-key-length    Specifies the length of the RSA key for the certificate, in bits. Supported key lengths include 1024, 2048 (default), 3072, and 4096 bits.
                        Other lengths, such as 1536 or 8192 bits, may be available but are less common due to performance considerations.
-h, --help              Print this help and exit.
-v, --verbose           Print script debug info.
EOF
	exit 0
}


# Parse the command-line parameters
function parse_param() {
	length=${length:-8}
	fqdn=${fqdn:-"www.pocdomain.com"}
	algorithm=${algorithm:-"rsa"}
	days=${days:-3650}
	show=${show:-"false"}
	certificate_dir=${certificate_dir:-"/tmp/cert"}
	password=${password:-""}
	country=${country:-"CN"}
	state=${state:-"ShangHai"}
	local=${local:-"ShangHai"}
	organization=${organization:-"Personal"}
	organizational_unit=${organizational_unit:-"IT Department"}
	common_name=${common_name:-"MY CA"}
	while :; do
		case "${1-}" in
		-a | --algorithm)
			algorithm=$2
			shift 2
			;;
		-f | --fqdn)
			fqdn=$2
			shift 2
			;;
		-t | --days)
			days=$2
			shift 2
			;;
		-p | --password)
			password=$2
			shift 2
			;;
		-l | --length)
			length=$2
			shift 2
			;;
		-s | --show)
			show="true"
			shift
			;;
		-C | --country)
			country=$2
			shift 2
			;;
		-S | --state)
			state=$2
			shift 2
			;;
		-L | --local)
			local=$2
			shift 2
			;;
		-O | --organization)
			organization=$2
			shift 2
			;;
		-o | --organizational-unit)
			organizational_unit=$2
			shift 2
			;;
		-N | --common-name)
			common_name=$2
			shift 2
			;;
		-e | --ec-name)
			ec_name=$2
			shift 2
			;;
		-r | --rsa-key-length)
			rsa_key_length=$2
			shift 2
			;;
		-h | --help) usage ;;
		-v | --verbose)
			set -x
			shift
			;;
		-?*) die "Unknown option: $1" ;;
		*) break ;;
		esac
	done
	log "👶 Starting up..."
}

# Generate a random password
function generate_random_pwd() {
	length=${length:-8}
	local seq=(0 1 2 3 4 5 6 7 8 9 a b c d e f g h i j k l m n o p q r s t u v w x y z A B C D E F G H I J K L M N O P Q R S T U V W X Y Z)
	local num_seq=${#seq[@]}
	local random_str=""

	for ((i = 0; i < length; i++)); do
		random_str+="${seq[$((RANDOM % num_seq))]}"
	done
	echo "$random_str"
}

# Validate the algorithm and key
function validate_algorithm_and_keys() {
	if [[ "$algorithm" == "rsa" ]]; then
		rsa_key_length=${rsa_key_length:-2048}
		if [[ -n "${ec_name:-}" ]]; then
			die "💥 The -e option cannot be used with RSA algorithm."
		fi
	elif [[ "$algorithm" == "ecc" ]]; then
		ec_name=${ec_name:-"secp256k1"}
		if [[ -n "${rsa_key_length:-}" ]]; then
			die "💥 The -r option cannot be used with ECC algorithm."
		fi
	else
		die "💥 Unsupported algorithm: $algorithm"
	fi

	if [[ -z "${password}" ]]; then
    password=$(generate_random_pwd)
  fi
}

function generate_certificate_dir() {
	validate_algorithm_and_keys
	certificate_dir=$(mktemp -d)
	if [[ ! "${certificate_dir}" || ! -d "${certificate_dir}" ]]; then
		die "💥 Could not create temporary working directory."
	else
		log "📁 Created temporary working directory $certificate_dir"
	fi
}

function certificate_file_name() {
	generate_certificate_dir
	fqdn=${fqdn}
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

function generate_ca_certificate_and_key() {
	local ca_subj="/C=${country}/ST=${state}/L=${local}/O=${organization}/OU=${organizational_unit}/CN=${fqdn}"
	certificate_file_name
	if [ ! -f "${ca_key_file}" ]; then
		case "${algorithm}" in
		rsa)
			# openssl genrsa -out ca.key 2048
			openssl genpkey -algorithm RSA -out ${ca_key_file} -pkeyopt rsa_keygen_bits:${rsa_key_length} >/dev/null 2>&1
			log "👍 Generated an RSA private CA key file"
			;;
		ecc)
			# openssl ecparam -name ${ecc_name} -genkey -noout -out ${ca_key_file} > /dev/null 2>&1
			openssl genpkey -algorithm EC -out ${ca_key_file} -pkeyopt ec_paramgen_curve:${ec_name} >/dev/null 2>&1
			log "👍 Generated an ECC private CA key file"
			;;
		*)
			die "usage:{$0 [-a rsa|ecc]}"
			;;
		esac
		openssl req -x509 -new -nodes -sha512 -days ${days} -subj "${ca_subj}" -key ${ca_key_file} -out ${ca_crt_file}
		if [ $? -eq 0 ]; then
			log "👍 Generated CA certificate file"
		else
			die "💥 Failed to generate CA certificate file"
		fi
	fi
}

function convert_certificate_formats() {
	cat ${srv_crt_file} ${ca_crt_file} >${srv_fullchain_file}
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
		printf "certificate password: ${password}\n" >"${certificate_dir}/.password"
		log "👍 The certificate password is in ${certificate_dir}/.password file"
	fi

	die "✅ Completed." 0
}

function generate_server_certificate_and_key() {
	local server_subj="/C=${country}/ST=${state}/L=${local}/O=${organization}/OU=${organizational_unit}/CN=${fqdn}"
	generate_ca_certificate_and_key
	if [ ! -f "${srv_key_file}" ]; then
		case "${algorithm}" in
		rsa)
			# openssl genrsa -out ca.key 2048, Equivalent to the following command:
			openssl genpkey -algorithm RSA -out ${srv_key_file} -pkeyopt rsa_keygen_bits:${rsa_key_length} >/dev/null 2>&1
			log "👍 Generated an RSA private server key file"
			;;
		ecc)
			#  openssl ecparam -name ${ecc_name} -genkey -noout -out ${ca_key_file},  Equivalent to the following command:
			openssl genpkey -algorithm EC -out ${srv_key_file} -pkeyopt ec_paramgen_curve:${ec_name} >/dev/null 2>&1
			log "👍 Generated an ECC private server key file"
			;;
		*)
			die "usage:{$0 [-a rsa|ecc]}"
			;;
		esac

		openssl req -new -sha256 -subj "${server_subj}" -key ${srv_key_file} -out ${srv_csr_file}
		log "👍 Generated server CSR (Certificate Signing Request) file"

		log "👍 Generating x509 v3 extension file"
		cat >${v3_extension_file} <<-EOF
			authorityKeyIdentifier=keyid,issuer
			basicConstraints=CA:FALSE
			keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
			extendedKeyUsage = serverAuth
			subjectAltName = @alt_names

			[alt_names]
			DNS.1=${fqdn}
		EOF
		openssl x509 -req -sha256 -days ${days} -extfile ${v3_extension_file} -CA ${ca_crt_file} -CAkey ${ca_key_file} -CAcreateserial -in ${srv_csr_file} -out ${srv_crt_file} >/dev/null 2>&1
		log "👍 Generated server certificate file"

		convert_certificate_formats
	fi
}

function main() {
	parse_param "$@"
	generate_server_certificate_and_key
}

main "$@"
