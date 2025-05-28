#!/bin/bash
set -e # Останавливать скрипт при ошибках
# set -x # Для отладки можно раскомментировать, чтобы видеть каждую выполняемую команду

# ---- Конфигурация ----
ROOT_CA_DIR="certs/ca"
ICA_DIR="certs/ica"

ROOT_CA_KEY="${ROOT_CA_DIR}/MyPracticumRootCA.key"
ROOT_CA_PEM="${ROOT_CA_DIR}/MyPracticumRootCA.pem"
ROOT_CA_CONF="${ROOT_CA_DIR}/root_ca.cnf"

ICA_KEY="${ICA_DIR}/MyPracticumServicesICA.key"
ICA_PEM="${ICA_DIR}/MyPracticumServicesICA.pem"
ICA_CSR="${ICA_DIR}/MyPracticumServicesICA.csr"
ICA_CONF="${ICA_DIR}/ica.cnf"

SERVER_EXT_CONF_TEMPLATE="certs/server.ext.tpl"
CLIENT_EXT_CONF_TEMPLATE="certs/client.ext.tpl"

CA_CHAIN_PEM="certs/ca_chain.pem"

# Очистка предыдущих сертификатов (опционально, для чистого запуска)
echo ">>> Cleaning up old certificates..."
rm -rf certs/*
echo ">>> Cleanup complete."

# ---- Создание директорий для УЦ ----
echo ">>> Creating CA directories..."
mkdir -p "${ROOT_CA_DIR}/db" "${ROOT_CA_DIR}/certs" "${ROOT_CA_DIR}/crl" "${ROOT_CA_DIR}/new_certs"
touch "${ROOT_CA_DIR}/db/index"
echo 1000 > "${ROOT_CA_DIR}/db/serial"
echo 1000 > "${ROOT_CA_DIR}/db/crlnumber"

mkdir -p "${ICA_DIR}/db" "${ICA_DIR}/certs" "${ICA_DIR}/crl" "${ICA_DIR}/new_certs"
touch "${ICA_DIR}/db/index"
echo 1000 > "${ICA_DIR}/db/serial"
echo 1000 > "${ICA_DIR}/db/crlnumber"
echo ">>> CA directories created."

# ---- Конфигурационный файл для Root CA ----
cat <<EOF > "${ROOT_CA_CONF}"
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ${ROOT_CA_DIR}
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/new_certs
database          = \$dir/db/index
serial            = \$dir/db/serial
RANDFILE          = \$dir/db/.rand

private_key       = \$dir/MyPracticumRootCA.key
certificate       = \$dir/MyPracticumRootCA.pem

crlnumber         = \$dir/db/crlnumber
crl               = \$dir/crl.pem
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 3650
preserve          = no
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca # Используется для самоподписанного Root CA

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Расширения для Root CA (самоподписанный)
[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

# Расширения для подписи Intermediate CA (корневым УЦ)
[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF

# ---- Конфигурационный файл для Intermediate CA ----
# Этот файл теперь будет меньше, так как расширения для конечных сертификатов
# будут полностью формироваться в файлах .ext, а не ссылаться на секции отсюда.
cat <<EOF > "${ICA_CONF}"
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ${ICA_DIR}
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/new_certs
database          = \$dir/db/index
serial            = \$dir/db/serial
RANDFILE          = \$dir/db/.rand

private_key       = \$dir/MyPracticumServicesICA.key
certificate       = \$dir/MyPracticumServicesICA.pem

crlnumber         = \$dir/db/crlnumber
crl               = \$dir/crl.pem
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 1825 # Срок действия сертификатов, выдаваемых этим CA
preserve          = no
policy            = policy_loose # ICA может быть менее строгим

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ] # Используется для генерации CSR самого ICA
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address
EOF

# ---- Шаблоны файлов расширений для конечных сертификатов ----

# certs/server.ext.tpl
cat <<EOF > "${SERVER_EXT_CONF_TEMPLATE}"
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
subjectAltName = @alt_names_here
[alt_names_here]
DNS.1 = localhost
# DNS.2 будет добавлен сюда скриптом
EOF

# certs/client.ext.tpl
cat <<EOF > "${CLIENT_EXT_CONF_TEMPLATE}"
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
subjectAltName = @alt_names_here
[alt_names_here]
# DNS.1 будет добавлен сюда скриптом
EOF


# ---- Генерация Root CA ----
echo ">>> Generating Root CA Key and Certificate..."
openssl genpkey -algorithm RSA -out "${ROOT_CA_KEY}" -pkeyopt rsa_keygen_bits:4096
openssl req -config "${ROOT_CA_CONF}" \
    -key "${ROOT_CA_KEY}" \
    -new -x509 -days 3650 -sha256 -extensions v3_ca \
    -out "${ROOT_CA_PEM}" \
    -subj "/C=RU/ST=Moscow/L=Moscow/O=MyPracticum/CN=MyPracticumRootCA"
echo ">>> Root CA Generated: ${ROOT_CA_PEM}"

# ---- Генерация Intermediate CA ----
echo ">>> Generating Intermediate CA Key and CSR..."
openssl genpkey -algorithm RSA -out "${ICA_KEY}" -pkeyopt rsa_keygen_bits:4096
openssl req -config "${ICA_CONF}" \
    -key "${ICA_KEY}" \
    -new -sha256 \
    -out "${ICA_CSR}" \
    -subj "/C=RU/ST=Moscow/L=Moscow/O=MyPracticum/OU=Services/CN=MyPracticumServicesICA"
echo ">>> Intermediate CA CSR Generated: ${ICA_CSR}"

echo ">>> Signing Intermediate CA CSR with Root CA..."
# Используем -batch для автоматического ответа 'y' на запросы
openssl ca -config "${ROOT_CA_CONF}" -extensions v3_intermediate_ca \
    -days 1825 -notext -md sha256 \
    -batch \
    -in "${ICA_CSR}" \
    -out "${ICA_PEM}"
echo ">>> Intermediate CA Certificate Signed: ${ICA_PEM}"

# ---- Функция для генерации сертификатов сущностей (сервисов/клиентов) ----
# $1: Тип сертификата ("server" или "client")
# $2: Имя сущности (например, "user_service" или "test_client")
# $3: Common Name для сертификата (например, "user.service.local")
# $4: (Опционально) Дополнительный DNS для SAN (если тип "server", для основного FQDN, если отличается от COMMON_NAME)
# ---- Функция для генерации сертификатов сущностей (сервисов/клиентов) ----
# $1: Тип сертификата ("server" или "client")
# $2: Имя сущности (например, "user_service" или "test_client")
# $3: Common Name для сертификата (например, "user.service.local")
# $4: (Опционально) Дополнительный DNS для SAN (если тип "server", для основного FQDN, если отличается от COMMON_NAME)
generate_entity_cert() {
    TYPE=$1
    ENTITY_NAME=$2
    COMMON_NAME=$3
    EXTRA_DNS=$4

    ENTITY_DIR="certs/${ENTITY_NAME}"
    mkdir -p "${ENTITY_DIR}"

    ENTITY_KEY="${ENTITY_DIR}/${TYPE}.key"
    ENTITY_CSR="${ENTITY_DIR}/${TYPE}.csr"
    ENTITY_PEM="${ENTITY_DIR}/${TYPE}.pem"
    ENTITY_EXT_CONF="${ENTITY_DIR}/${TYPE}.ext" # Временный файл расширений для этой сущности

    echo ">>> Generating ${TYPE} certificate for ${ENTITY_NAME} (CN: ${COMMON_NAME})..."

    # 1. Генерация приватного ключа
    openssl genpkey -algorithm RSA -out "${ENTITY_KEY}" -pkeyopt rsa_keygen_bits:2048

    # 2. Создание файла расширений для этой сущности
    if [ "${TYPE}" == "server" ]; then
        cp "${SERVER_EXT_CONF_TEMPLATE}" "${ENTITY_EXT_CONF}"
        if [ -n "${EXTRA_DNS}" ] && [ "${EXTRA_DNS}" != "${COMMON_NAME}" ]; then
             # EXTRA_DNS (основной FQDN) идет как DNS.2, COMMON_NAME (если нужен отдельно) как DNS.3
             sed -i "s/# DNS.2 будет добавлен сюда скриптом/DNS.2 = ${EXTRA_DNS}\nDNS.3 = ${COMMON_NAME}/" "${ENTITY_EXT_CONF}"
        elif [ -n "${COMMON_NAME}" ]; then # Если EXTRA_DNS не задан или совпадает, используем COMMON_NAME
             sed -i "s/# DNS.2 будет добавлен сюда скриптом/DNS.2 = ${COMMON_NAME}/" "${ENTITY_EXT_CONF}"
        else
             # Если и COMMON_NAME пуст (маловероятно), удаляем строчку-комментарий
             sed -i "/# DNS.2 будет добавлен сюда скриптом/d" "${ENTITY_EXT_CONF}"
        fi

    elif [ "${TYPE}" == "client" ]; then
        cp "${CLIENT_EXT_CONF_TEMPLATE}" "${ENTITY_EXT_CONF}"
        if [ -n "${COMMON_NAME}" ]; then
            sed -i "s/# DNS.1 будет добавлен сюда скриптом/DNS.1 = ${COMMON_NAME}/" "${ENTITY_EXT_CONF}"
        else
            sed -i "/# DNS.1 будет добавлен сюда скриптом/d" "${ENTITY_EXT_CONF}"
        fi
    else
        echo "Error: Unknown certificate type '${TYPE}'"
        exit 1
    fi

    # 3. Генерация CSR
    SUBJECT_OU="Services" # По умолчанию
    if [ "${TYPE}" == "client" ]; then
      SUBJECT_OU="Clients"
      if [ "${ENTITY_NAME}" == "test_client" ]; then
        SUBJECT_OU="Testing"
      fi
    fi
    openssl req -config "${ICA_CONF}" \
        -key "${ENTITY_KEY}" \
        -new -sha256 \
        -out "${ENTITY_CSR}" \
        -subj "/C=RU/ST=Moscow/L=Moscow/O=MyPracticum/OU=${SUBJECT_OU}/CN=${COMMON_NAME}"

    # 4. Подписание CSR с помощью Intermediate CA
    # Убрали -extensions, так как все расширения теперь в -extfile
    openssl ca -config "${ICA_CONF}" \
        -days 375 -notext -md sha256 \
        -batch \
        -in "${ENTITY_CSR}" \
        -out "${ENTITY_PEM}" \
        -extfile "${ENTITY_EXT_CONF}"

    echo ">>> ${TYPE} certificate for ${ENTITY_NAME} generated: ${ENTITY_PEM}"
    # rm "${ENTITY_CSR}" # Можно оставить CSR для отладки или удалить
    # rm "${ENTITY_EXT_CONF}" # Очистка временных файлов
}

# ---- Генерация сертификатов для сервисов (серверные) ----
# Для серверных сертификатов, если вы обращаетесь к ним по localhost И по user.service.local,
# то оба должны быть в SAN. localhost уже есть (DNS.1). COMMON_NAME (user.service.local) будет DNS.2.
generate_entity_cert "server" "user_service" "user.service.local"
generate_entity_cert "server" "transaction_service" "transaction.service.local"
generate_entity_cert "server" "report_service" "report.service.local"

# ---- Генерация сертификатов для клиентов ----
generate_entity_cert "client" "test_client" "test.client.local"
# Клиентский сертификат для report_service (когда он обращается к transaction_service)
generate_entity_cert "client" "report_service" "report.service.client.local"

# ---- Генерация ключей для JWT (только для user_service) ----
echo ">>> Generating RSA keys for JWT (user_service)..."
USER_SERVICE_CERT_DIR="certs/user_service"
mkdir -p ${USER_SERVICE_CERT_DIR} # Убедимся, что директория существует
openssl genpkey -algorithm RSA -out "${USER_SERVICE_CERT_DIR}/jwt_private.pem" -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in "${USER_SERVICE_CERT_DIR}/jwt_private.pem" -out "${USER_SERVICE_CERT_DIR}/jwt_public.pem"
echo ">>> JWT keys generated."

# ---- Создание цепочки сертификатов CA ----
echo ">>> Creating CA chain file..."
cat "${ICA_PEM}" "${ROOT_CA_PEM}" > "${CA_CHAIN_PEM}"
echo ">>> CA chain file created: ${CA_CHAIN_PEM}"

echo "-----------------------------------------------------"
echo "PKI Generation Complete!"
echo "-----------------------------------------------------"
echo "Important files:"
echo "Root CA: ${ROOT_CA_PEM} (and ${ROOT_CA_KEY})"
echo "Intermediate CA: ${ICA_PEM} (and ${ICA_KEY})"
echo "CA Chain (for clients/servers to trust): ${CA_CHAIN_PEM}"
echo ""
echo "Server certs/keys are in certs/<service_name>/server.pem and server.key"
echo "Client certs/keys are in certs/<client_name_or_service_acting_as_client>/client.pem and client.key"
echo "JWT keys for user_service are in certs/user_service/jwt_private.pem and jwt_public.pem"
echo "-----------------------------------------------------"