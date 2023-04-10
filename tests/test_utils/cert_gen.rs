use std::net::IpAddr;
use rcgen::{BasicConstraints, CertificateSigningRequest, DnType, IsCa, SanType, ExtendedKeyUsagePurpose, KeyUsagePurpose, DistinguishedName, CertificateParams, Certificate};

pub struct ServerCertificate {
    pub private_key_pem: String,

    // Server certificate only; does not include complete certificate chain.
    pub signed_certificate_pem: String,
}

pub fn gen_cert_for_ca() -> Certificate {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "USA");
    dn.push(DnType::CommonName, "Auto-Generated CA");

    let mut params = CertificateParams::default();

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    Certificate::from_params(params)
        .unwrap()
}

pub fn gen_cert_for_server(ca: &Certificate, ip: IpAddr) -> ServerCertificate {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "USA");
    dn.push(DnType::CommonName, "Auto-Generated Server");

    let mut params = CertificateParams::default();

    params.is_ca = IsCa::NoCa;
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::IpAddress(ip)];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let unsigned = Certificate::from_params(params)
        .unwrap();

    let request_pem = unsigned.serialize_request_pem()
        .unwrap();

    let csr = CertificateSigningRequest::from_pem(&request_pem)
        .unwrap();

    let signed_pem = csr.serialize_pem_with_signer(&ca)
        .unwrap();

    ServerCertificate {
        private_key_pem: unsigned.serialize_private_key_pem(),
        signed_certificate_pem: signed_pem
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::Ipv4Addr;
    use std::thread;
    use native_tls::{HandshakeError, Identity, TlsStream};
    use x509_parser::extensions::GeneralName;
    use x509_parser::nom::AsBytes;
    use super::{gen_cert_for_ca, gen_cert_for_server};

    fn map_tls_io_error<S>(tls_result: Result<TlsStream<S>, HandshakeError<S>>) -> Result<TlsStream<S>, String>
    where
        S: io::Read + io::Write
    {
        match tls_result {
            Ok(stream) => Ok(stream),
            Err(he) => {
                match he {
                    HandshakeError::Failure(e) => Err(format!("{}", e)),
                    // Can't directly unwrap because TlsStream doesn't implement Debug trait
                    HandshakeError::WouldBlock(_) => Err("Would block".into())
                }
            }
        }
    }

    #[test]
    fn validate_certificate_generation_with_tls() {
        let ca = gen_cert_for_ca();

        println!("CA private key:\n{}", ca.serialize_private_key_pem());
        println!();
        println!("CA certificate:\n{}", ca.serialize_pem().unwrap());

        let host_ip = Ipv4Addr::new(10, 1, 2, 3);
        let host_cert = gen_cert_for_server(&ca, host_ip.into());

        let parsed_host_pem = pem::parse(&host_cert.signed_certificate_pem)
            .unwrap();

        let parsed_host_der = parsed_host_pem.contents();
        let parsed_host_der_bytes = parsed_host_der.as_bytes();

        let (_, parsed_host_x509) = x509_parser::parse_x509_certificate(parsed_host_der_bytes)
            .unwrap();

        let san = parsed_host_x509.subject_alternative_name()
            .unwrap()
            .unwrap();

        for gn in &san.value.general_names {
            if let GeneralName::IPAddress(encoded) = gn {
                if encoded.len() == 4 {
                    let san_ip = Ipv4Addr::new(encoded[0], encoded[1], encoded[2], encoded[3]);
                    println!("san ip v4 address: {}", san_ip);
                    assert_eq!(host_ip, san_ip);
                }
            }

            println!("san general name: {}", gn);
        }

        println!("Preparing to verify with tls");

        let leaf_then_ca = format!("{}{}", host_cert.signed_certificate_pem, ca.serialize_pem().unwrap());

        println!();
        println!("Server private key:\n{}", host_cert.private_key_pem);
        println!("Server chain:\n{}\n", leaf_then_ca);

        // For use by server
        let server_id = Identity::from_pkcs8(
            leaf_then_ca.as_bytes(),
            host_cert.private_key_pem.as_bytes()
        )
            .unwrap();

        // For use by client
        let native_ca_cert = native_tls::Certificate::from_pem(ca.serialize_pem().unwrap().as_bytes())
            .unwrap();

        let (p_client, p_server) = pipe::bipipe();

        let t_client = thread::spawn(move || {
            println!("Client creating");

            let test_client = native_tls::TlsConnector::builder()
                .add_root_certificate(native_ca_cert)
                .build()
                .unwrap();

            println!("Client connecting");

            let _stream = map_tls_io_error(test_client.connect("10.1.2.3", p_client))
                .unwrap();

            println!("Client connected");
        });

        let t_server = thread::spawn(move || {
            println!("Server creating");

            let test_server = native_tls::TlsAcceptor::new(server_id)
                .unwrap();

            println!("Server accepting");

            let _server_tls_stream = map_tls_io_error(test_server.accept(p_server))
                .unwrap();

            println!("Server accepted");
        });

        println!("Joining client");
        t_client.join()
            .unwrap();

        println!("Joining server");
        t_server.join()
            .unwrap();
    }
}