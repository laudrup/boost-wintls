# store some temporary files in a subfolder that can be removed later
mkdir -p tmp

# Generate self signed Root certificate valid for 100 years
openssl req -days 36525 -nodes -new -x509 -keyout ca_root.key -out ca_root.crt -config conf/ca_root.conf
# Request intermediate certificate
openssl req -nodes -new -keyout ca_intermediate.key -out tmp/ca_intermediate.csr -config conf/ca_intermediate.conf
# Request leaf certificate
openssl req -nodes -new -keyout leaf.key -out tmp/leaf.csr -config conf/leaf.conf

# Setup for signing the subordinate certificates
touch tmp/certindex
echo 01 > tmp/certserial
echo 01 > tmp/crlnumber

# Sign intermediate certificate
openssl x509 -req -CAcreateserial -days 36525 -extensions req_v3_ca -extfile conf/ca_intermediate.conf -in tmp/ca_intermediate.csr -out ca_intermediate.crt -CAkey ca_root.key -CA ca_root.crt
# Sign leaf certificate
openssl x509 -req -CAcreateserial -days 36525 -extensions req_v3_usr -extfile conf/leaf.conf -in tmp/leaf.csr -out leaf.crt -CAkey ca_intermediate.key -CA ca_intermediate.crt

# Create certificate chain for leaf.crt
cat leaf.crt ca_intermediate.crt ca_root.crt > leaf_chain.pem

# Generate empty CRL
openssl ca -config conf/ca_root.conf -gencrl -keyfile ca_root.key -cert ca_root.crt -out ca_root_empty.crl.pem
openssl ca -config conf/ca_intermediate.conf -gencrl -keyfile ca_intermediate.key -cert ca_intermediate.crt -out ca_intermediate_empty.crl.pem

# revoke leaf.crt
openssl ca -config conf/ca_intermediate.conf -revoke leaf.crt -keyfile ca_intermediate.key -cert ca_intermediate.crt

# revoke ca_intermediate.crt
openssl ca -config conf/ca_root.conf -revoke ca_intermediate.crt -keyfile ca_root.key -cert ca_root.crt

# Generate CRLs including the revoked certificates
openssl ca -config conf/ca_root.conf -gencrl -keyfile ca_root.key -cert ca_root.crt -out ca_root_intermediate_revoked.crl.pem
openssl ca -config conf/ca_intermediate.conf -gencrl -keyfile ca_intermediate.key -cert ca_intermediate.crt -out ca_intermediate_leaf_revoked.crl.pem

# keep only the files actually used from the unit test
rm -r tmp
rm *.srl
rm *.key
