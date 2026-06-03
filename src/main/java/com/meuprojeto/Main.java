package com.meuprojeto;

import java.io.IOException;
import java.math.BigInteger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SignatureException;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import io.github.cdimascio.dotenv.Dotenv;

import java.security.interfaces.RSAPublicKey;

public class Main {

    public static String generateXpaytoken(String resourcePath, String queryString, String requestBody, String sharedSecret) throws SignatureException {  
        String timestamp = timeStamp();  
        String beforeHash = timestamp + resourcePath + queryString + requestBody;
        String hash = hmacSha256Digest(beforeHash, sharedSecret);  
        String token = "xv2:" + timestamp + ":" + hash;  
        return token;  
    }  

    private static String timeStamp() {  
            return String.valueOf(System.currentTimeMillis()/ 1000L);  
        }  

    private static String hmacSha256Digest(String data, String sharedSecret)  
            throws SignatureException {  
        return getDigest("HmacSHA256", sharedSecret, data, true);  
    }  

    private static String getDigest(String algorithm, String sharedSecret, String data,  boolean toLower) throws SignatureException {  
        try {  
            Mac sha256HMAC = Mac.getInstance(algorithm);  
            SecretKeySpec secretKey = new SecretKeySpec(sharedSecret.getBytes(StandardCharsets.UTF_8), algorithm);  
            sha256HMAC.init(secretKey);  

            byte[] hashByte = sha256HMAC.doFinal(data.getBytes(StandardCharsets.UTF_8));  
            String hashString = toHex(hashByte);  

            return toLower ? hashString.toLowerCase() : hashString;
        } catch (Exception e) {  
            throw new SignatureException(e);  
        }  
    }  

    private static String toHex(byte[] bytes) {  
        BigInteger bi = new BigInteger(1, bytes);  
        return String.format("%0" + (bytes.length << 1) + "X", bi);  
    }

    public static void main(String[] args) throws SignatureException, GenericSecurityException, GeneralSecurityException, IOException {
        // Carregar variáveis de ambiente do arquivo .env
        Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();
        
        String resourcePath = "provisioning/cardData/googlePay";

        String apiKey = dotenv.get("API_KEY");
        String sharedSecret = dotenv.get("SHARED_SECRET");

        System.out.println("API Key: " + apiKey);
        System.out.println("Shared Secret: " + sharedSecret);
        
        // Remove aspas se existirem
        if (sharedSecret != null && sharedSecret.startsWith("\"") && sharedSecret.endsWith("\"")) {
            sharedSecret = sharedSecret.substring(1, sharedSecret.length() - 1);
        }
        
        String queryString = "apikey="+apiKey;
        
        // String payload = "{\"vCardID\": \"v-123-e3fee947-4ee4-4a49-83bf-3b3ae6103b01\",\"deviceID\":\"uztEQocBRFrbK5hCgcDbxqw_\",\"clientCustomerID\":\"_Dnr1RNseIpKPenh3fK18nrT\",\"tokenServiceProvider\":\"V\"}";
        
        String plainText = "{\"accountNumber\":\"4514231274459132\",\"nameOnCard\":\"Cody Payne\",\"cvv2\":\"123\",\"expirationDate\":{\"month\":\"12\",\"year\":\"2030\"}}";
        String kid = "83F4EEB2";
        RSAPublicKey rsaPubKey = CertificateUtils.loadPublicKeyFromFile("src/main/resources/VisaPublicKey_ForEncryption_Sbx_Cert.pem");
        String jwe = EncryptionUtils.createJwe(plainText, kid, rsaPubKey, JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, null);
        String payload = "{\"encCard\":\"" + jwe + "\",\"deviceID\":\"uztEQocBRFrbK5hCgcDbxqw_\",\"clientCustomerID\":\"_Dnr1RNseIpKPenh3fK18nrT\",\"tokenServiceProvider\":\"V\"}";


        String xPayToken = Main.generateXpaytoken(resourcePath, queryString, payload, sharedSecret);

        System.out.println(xPayToken);

        System.out.println("\n"+payload);
    }
}

