/*
 * Copyright 2019 The FATE Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webank.ai.fate.serving.common.utils;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import sun.misc.HexDumpEncoder;
import sun.security.provider.certpath.CertId;
import sun.security.provider.certpath.OCSP;
import sun.security.provider.certpath.OCSPResponse;
import sun.security.util.Debug;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.*;

import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class HttpsClient {
    public static final String tabs = "%2F", equalSign = "%3D";

    public static X509Certificate caX509Certificate;
    //private static final String caPath = "D:/FATE Chain/test/fdn-ca.crt";
    //private static final String clientCertPath = "D:/FATE Chain/test/fdn-ca/free-inference-exchange-fdn.webank.com.crt";
    //private static final String clientKeyPath = "D:/FATE Chain/test/fdn-ca/free-inference-exchange-fdn.webank.com.key";

    // Verifier manager
    //public static X509TrustManager sunJSSEX509TrustManager;
    //public static HostnameVerifier hostnameVerifier;
    //public static X509TrustManager x509TrustManager;

    // SSL Context
    //public static SSLContext sslContext;
    private final SSLSocketFactory socketFactory;

    // Whether to reuse ssl socket factory
    //public static final boolean reuseFactory = true;
    // Whether the request keeps a long connection
    public static final boolean isKeepAlive = false;
    // Whether the check server certificate state
    public static final boolean checkServer = false;

    public HttpsClient() throws KeyManagementException, NoSuchAlgorithmException {
        this.socketFactory = getSslFactory();
    }

    public HttpsClient(String caPath, String clientCertPath, String clientKeyPath) throws Exception {
        this.socketFactory = getSslFactory(caPath, clientCertPath, clientKeyPath);
    }

    public static void main(String[] args) throws Exception {
        String data = "{\n" +
                "  \"header\": {\n" +
                "    \"task\": {\n" +
                "      \"model\": {\n" +
                "        \"namespace\": \"testNamespace\",\n" +
                "        \"tableName\": \"testTablename\"\n" +
                "      }\n" +
                "    },\n" +
                "    \"src\": {\n" +
                "      \"name\": \"partnerPartyName\",\n" +
                "      \"partyId\": \"9999\",\n" +
                "      \"role\": \"serving\"\n" +
                "    },\n" +
                "    \"dst\": {\n" +
                "      \"name\": \"partyName\",\n" +
                "      \"partyId\": \"10000\",\n" +
                "      \"role\": \"serving\"\n" +
                "    },\n" +
                "    \"command\": {\n" +
                "      \"name\": \"uncaryCall\"\n" +
                "    },\n" +
                "    \"operator\": \"210\"\n" +
                "  },\n" +
                "  \"body\": {\n" +
                "    \"value\": \"Im15IG5hbWUgaXMgdGVzdCI=\"\n" +
                "  },\n" +
                "  \"auth\": {\n" +
                "    \"version\": \"210\"\n" +
                "  }\n" +
                "}";
        HttpsClient httpsClient = new HttpsClient();
        String post = httpsClient.request("https://172.16.153.223:8060/unary", "POST", data);
        System.out.println(post);
    }

    public String request(String httpsUrl, String requestMethod, String requestBody) throws Exception {
        // Set hostname verifier
        HttpsURLConnection.setDefaultHostnameVerifier(HttpsClient.HostnameVerifier2.getInstance());

        URL url = new URL(httpsUrl);
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();

        con.setSSLSocketFactory(this.socketFactory);
        con.setRequestMethod(requestMethod);
        con.setDoOutput(true);
        con.setDoInput(true);
        con.setConnectTimeout(2000);
        con.setReadTimeout(3000);
        con.setInstanceFollowRedirects(true);

        // Set request header
        con.setRequestProperty("Content-Type", "application/json");
        con.setRequestProperty("Accept-Charset", "utf-8");
        con.setRequestProperty("Connection", isKeepAlive ? "Keep-Alive" : "close");

        // Send request body
        if (requestBody != null && !requestBody.trim().equals("")) {
            con.setRequestProperty("Content-Length", "" + requestBody.length());
            PrintWriter out = new PrintWriter(new OutputStreamWriter(con.getOutputStream(), StandardCharsets.UTF_8));
            out.write(requestBody);
            out.flush();
            out.close();
        }

        // Read response
        StringBuilder result = new StringBuilder("null");
        try (InputStreamReader in = new InputStreamReader(con.getInputStream(), StandardCharsets.UTF_8);
             BufferedReader br = new BufferedReader(in)) {
            result = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                result.append(line);
            }
        } catch (IOException e) {
            // e.printStackTrace();
        }
        return result.toString();
    }

    // get ssl factory
    private static SSLSocketFactory getSslFactory(String caPath, String clientCertPath, String clientKeyPath) throws Exception {
        KeyStore keyStore = getKeyStore(caPath, clientCertPath, clientKeyPath);
        // Initialize the ssl context object
        SSLContext sslContext = SSLContext.getInstance("SSL");
        TrustManager[] tm = {HttpsClient.X509TrustManager2.getInstance(keyStore)};
        // Load client certificate
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, "123456".toCharArray());
        sslContext.init(kmf.getKeyManagers(), tm, new SecureRandom());
        // Initialize the factory
        return sslContext.getSocketFactory();
    }

    // no certificate
    private static SSLSocketFactory getSslFactory() throws NoSuchAlgorithmException, KeyManagementException {
        // Initialize the ssl context object
        SSLContext sslContext = SSLContext.getInstance("TLS");
        TrustManager[] tm = {HttpsClient.X509TrustManager2.getInstance()};
        sslContext.init(null, tm, new SecureRandom());
        // Initialize the factory
        return sslContext.getSocketFactory();
    }

    // Synthetic certificate keystore
    private static KeyStore getKeyStore(String caPath, String clientCertPath, String clientKeyPath) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(null);
        keyStore.setKeyEntry("chain", importPrivateKey(clientKeyPath), "123456".toCharArray(),
                new Certificate[]{importCert(clientCertPath), caX509Certificate = ((X509Certificate) importCert(caPath))});
        return keyStore;
    }

    public static class HostnameVerifier2 implements HostnameVerifier {

        @Override
        public boolean verify(String s, SSLSession sslSession) {
            return true;
        }

        public static HttpsClient.HostnameVerifier2 getInstance() {
            return new HttpsClient.HostnameVerifier2();
        }
    }

    public static class X509TrustManager2 implements X509TrustManager {
        private final X509TrustManager x509TrustManager;

        public X509TrustManager2(X509TrustManager x509TrustManager) {
            this.x509TrustManager = x509TrustManager;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            try {
                if (this.x509TrustManager == null) return;
                this.x509TrustManager.checkClientTrusted(chain, authType);
            } catch (CertificateException exc) {
                // System.out.println(exc.getMessage());
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            // sunJSSEX509TrustManager.checkServerTrusted(chain, authType);
            if (checkServer) {
                for (X509Certificate x509Certificate : chain) {
                    // Use ca certificate verify
                    verify(caX509Certificate, x509Certificate);

                    // Send ocsp request verify
                    ocspVerify(x509Certificate);
                }
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            if (this.x509TrustManager == null) return null;
            return this.x509TrustManager.getAcceptedIssuers();
        }

        public static HttpsClient.X509TrustManager2 getInstance() {
            return new HttpsClient.X509TrustManager2(null);
        }

        public static HttpsClient.X509TrustManager2 getInstance(KeyStore keyStore) throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException {
            X509TrustManager x509TrustManager = null;
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509", "SunJSSE");
            tmf.init(keyStore);
            TrustManager[] tms = tmf.getTrustManagers();
            for (TrustManager tm : tms) {
                if (tm instanceof X509TrustManager) {
                    x509TrustManager = (X509TrustManager) tm;
                    break;
                }
            }
            return new HttpsClient.X509TrustManager2(x509TrustManager);
        }
    }

    // Import certificate
    public static Certificate importCert(String certFile) throws Exception {
        try (FileInputStream certStream = new FileInputStream(certFile)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return cf.generateCertificate(certStream);
        }
    }

    // Import private key
    public static PrivateKey importPrivateKey(String privateKeyFile) throws Exception {
        try (FileInputStream keyStream = new FileInputStream(privateKeyFile)) {
            String space = "";
            byte[] bytes = new byte[keyStream.available()];
            int length = keyStream.read(bytes);
            String keyString = new String(bytes, 0, length);
            if (keyString.startsWith("-----BEGIN PRIVATE KEY-----\n")) {
                keyString = keyString.replace("-----BEGIN PRIVATE KEY-----\n", space).replace("-----END PRIVATE KEY-----", space);
            }
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(new BASE64Decoder().decodeBuffer(keyString));
            return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        }
    }

    // Verify that the certificate if expired, and is issued for the root certificate
    public static void verify(X509Certificate superiorCert, X509Certificate issueCert) throws CertificateException {
        try {
            issueCert.checkValidity();
            issueCert.verify(superiorCert.getPublicKey());
        } catch (Exception e) {
            throw new CertificateException(e);
        }
    }

    // Obtain ocsp service address from the certificate and verify the validity of the certificate
    public static void ocspVerify(X509Certificate x509Certificate) throws CertificateException {
        X509CertImpl x509Cert = (X509CertImpl) x509Certificate;
        AuthorityInfoAccessExtension accessExtension = x509Cert.getAuthorityInfoAccessExtension();
        List<AccessDescription> accessDescriptions = accessExtension.getAccessDescriptions();
        for (AccessDescription accessDescription : accessDescriptions) {
            String anObject = accessDescription.getAccessMethod().toString();
            if ("ocsp".equals(anObject) || "1.3.6.1.5.5.7.48.1".equals(anObject)) {
                GeneralName accessLocation = accessDescription.getAccessLocation();
                URI ocspUrl = ((URIName) accessLocation.getName()).getURI();
                goSendOCSP(ocspUrl.toString(), x509Cert);
            }
        }
    }

    // Send ocsp request
    public static void goSendOCSP(String ocspUrl, X509CertImpl x509Certificate) throws CertificateException {
        try {
            URL url = new URL(ocspUrl + "/" + getOcspRequestData(x509Certificate));
            HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setConnectTimeout(5000);
            urlConnection.setReadTimeout(15000);
            urlConnection.setRequestMethod("GET");
            urlConnection.setDoOutput(true);
            urlConnection.setDoInput(true);
            urlConnection.setRequestProperty("Content-type", "application/ocsp-request");

            try (InputStream br = urlConnection.getInputStream();
                 ByteArrayOutputStream aos = new ByteArrayOutputStream()
            ) {
                int len;
                byte[] bytes = new byte[br.available()];
                while ((len = br.read(bytes)) != -1) {
                    aos.write(bytes, 0, len);
                }
                OCSPResponse ocspResponse = new OCSPResponse(aos.toByteArray());
                OCSPResponse.ResponseStatus responseStatus = ocspResponse.getResponseStatus();

                if (!responseStatus.equals(OCSPResponse.ResponseStatus.SUCCESSFUL)) {
                    throw new CertificateException("ocsp request failed, request state: " + responseStatus);
                }

                Set<CertId> certIds = ocspResponse.getCertIds();
                for (CertId certId : certIds) {
                    // Date nextUpdate = singleResponse.getNextUpdate();
                    // CRLReason revocationReason = singleResponse.getRevocationReason();
                    // Date thisUpdate = singleResponse.getThisUpdate();
                    OCSPResponse.SingleResponse singleResponse = ocspResponse.getSingleResponse(certId);
                    OCSP.RevocationStatus.CertStatus certStatus = singleResponse.getCertStatus();
                    System.out.println("server certificate serial number: " + certId.getSerialNumber().toString(16) + ", status: " + certStatus);

                    if (!OCSP.RevocationStatus.CertStatus.GOOD.equals(certStatus)) {
                        // throw new CertificateException("服务器验证失败, 证书状态: " + certStatus);
                    }
                }


            } catch (Exception e) {
                throw new CertificateException(e);
            }
        } catch (IOException e) {
            throw new CertificateException(e);
        }
    }

    // get ocsp request bytes
    private static byte[] getOcspRequestBytesData(X509CertImpl x509Certificate) throws IOException {
        return new HttpsClient.OCSPRequest(new CertId(x509Certificate, x509Certificate.getSerialNumberObject())).encodeBytes();
    }

    // get Base64 encode ocsp request url string parameter
    private static String getOcspRequestData(X509CertImpl certificate) throws IOException {
        CertId certId = new CertId(certificate, certificate.getSerialNumberObject());
        HttpsClient.OCSPRequest request = new HttpsClient.OCSPRequest(certId);
        String encodeBuffer = new BASE64Encoder().encodeBuffer(request.encodeBytes());
        return encodeBuffer.replace("\r\n", "").replace("/", tabs).replace("=", equalSign);
    }

    // OCSPRequest
    private static class OCSPRequest {
        private static final Debug debug = Debug.getInstance("certpath");
        private static final boolean dump;
        private final List<CertId> certIds;
        private final List<java.security.cert.Extension> extensions;
        private byte[] nonce;

        public OCSPRequest(CertId certId) {
            this(Collections.singletonList(certId));
        }

        public OCSPRequest(List<CertId> certIdList) {
            this.certIds = certIdList;
            this.extensions = Collections.emptyList();
        }

        public OCSPRequest(List<CertId> certIdList, List<java.security.cert.Extension> extensionList) {
            this.certIds = certIdList;
            this.extensions = extensionList;
        }

        public byte[] encodeBytes() throws IOException {
            DerOutputStream fillDOS = new DerOutputStream();
            DerOutputStream certIdDOS = new DerOutputStream();

            for (CertId certId : this.certIds) {
                DerOutputStream encodeDos = new DerOutputStream();
                certId.encode(encodeDos);
                certIdDOS.write((byte) 48, encodeDos);
            }

            fillDOS.write((byte) 48, certIdDOS);
            DerOutputStream extensionDos;
            DerOutputStream endDos;
            if (!this.extensions.isEmpty()) {
                extensionDos = new DerOutputStream();

                for (java.security.cert.Extension extension : this.extensions) {
                    extension.encode(extensionDos);
                    if (extension.getId().equals(PKIXExtensions.OCSPNonce_Id.toString())) {
                        this.nonce = extension.getValue();
                    }
                }

                endDos = new DerOutputStream();
                endDos.write((byte) 48, extensionDos);
                fillDOS.write(DerValue.createTag((byte) -128, true, (byte) 2), endDos);
            }

            extensionDos = new DerOutputStream();
            extensionDos.write((byte) 48, fillDOS);
            endDos = new DerOutputStream();
            endDos.write((byte) 48, extensionDos);
            byte[] bytes = endDos.toByteArray();
            if (dump) {
                HexDumpEncoder dumpEncoder = new HexDumpEncoder();
                debug.println("OCSPRequest bytes...\n\n" + dumpEncoder.encode(bytes) + "\n");
            }

            return bytes;
        }

        public List<CertId> getCertIds() {
            return this.certIds;
        }

        public byte[] getNonce() {
            return this.nonce;
        }

        static {
            dump = debug != null && Debug.isOn("ocsp");
        }
    }
}
