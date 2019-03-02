from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from flask import Flask, render_template, request

app = Flask(__name__)


def gen_rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def gen_csr(key, c, s, l, o, ou, cn):
    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, c),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, s),
        x509.NameAttribute(NameOID.LOCALITY_NAME, l),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])).sign(key, hashes.SHA256(), default_backend())


@app.route('/')
def form():
    return render_template('form.html')


@app.route('/confirm', methods=['POST', 'GET'])
def confirm():
    if request.method == 'POST':
        country = request.form["Country"]
        state = request.form["State"]
        locality = request.form["Locality"]
        organization = request.form["Organization"]
        organization_unit = request.form["OrganizationUnit"]
        fqdn = request.form["CommonName"]
        result = request.form

        key = gen_rsa_key()

        privete_key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())

        csr = gen_csr(
            key,
            country,
            state,
            locality,
            organization,
            organization_unit,
            fqdn)

        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        return render_template("confirm.html", privete_key_pem=privete_key_pem.decode('utf-8'), csr_pem=csr_pem.decode('utf-8'), result=result)


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
