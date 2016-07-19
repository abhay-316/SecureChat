import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

import sun.misc.BASE64Decoder;


public class RSA_433 implements CipherInterface {
	private static final String TAG = "RSA_433";
	/*
	 * basicly you divide the key length with 8 -11(if you have padding). 
	 * For example if you have a 2048bit key you can encrypt 2048/8 = 256 bytes 
	 * (- 11 bytes if you have padding).
	 */
	private static final String CIPHER_MODE = "RSA/ECB/PKCS1Padding";
	private static final int MAX_CIPHER_BLOCK_LEN = 256;
	private static final int PADING_LEN = 11;
	
	// Private key file using PKCS #1 encoding
	public static final String P1_BEGIN_MARKER 
		= "-----BEGIN RSA PRIVATE KEY"; //$NON-NLS-1$
	public static final String P1_END_MARKER
	    = "-----END RSA PRIVATE KEY"; //$NON-NLS-1$

	// Private key file using PKCS #8 encoding
	public static final String P8_BEGIN_MARKER 
		= "-----BEGIN PRIVATE KEY"; //$NON-NLS-1$
	public static final String P8_END_MARKER
    	= "-----END PRIVATE KEY"; //$NON-NLS-1$
	
	private RSAPublicKey pubKey;
	private RSAPrivateKey  privKey;
	private Cipher cipher;

	/**
	 * Generate public key / private key for RSA
	 */
	public void setKey(String path) throws InvalidKeyException,
			InvalidKeySpecException {
		// TODO Auto-generated method stub

		File f = new File(path);
		try {

			FileInputStream fis = new FileInputStream(f);
			DataInputStream dis = new DataInputStream(fis);
			byte[] keyBytes = new byte[(int) f.length()];
			dis.readFully(keyBytes);
			dis.close();
			KeyFactory kf = KeyFactory.getInstance("RSA");
			if (path.contains("pri")) {// generate private key
				String temp = new String(keyBytes);
				if( temp.contains(P1_END_MARKER) ){// PKCS#1 format key
					String privKeyPEM = temp.replace("-----BEGIN RSA PRIVATE KEY-----", "");
					privKeyPEM = privKeyPEM.replace("-----END RSA PRIVATE KEY-----", "");
					BASE64Decoder b64 = new BASE64Decoder();
					byte[] decoded = b64.decodeBuffer(privKeyPEM);
					RSAPrivateCrtKeySpec keySpec = getRSAKeySpec(decoded);
					privKey = (RSAPrivateKey) kf.generatePrivate(keySpec);
					
				} else if (temp.contains(P8_END_MARKER)){// PKCS#8 format key
					String privKeyPEM = temp.replace("-----BEGIN PRIVATE KEY-----", "");
					privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
					BASE64Decoder b64 = new BASE64Decoder();
					byte[] decoded = b64.decodeBuffer(privKeyPEM);
					PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
					privKey = (RSAPrivateKey) kf.generatePrivate(spec);
					
				}
			} else {                    // generate public key
				String temp = new String(keyBytes);
				String publicKeyPEM = temp.replace("-----BEGIN PUBLIC KEY-----\n", "");
				publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
				BASE64Decoder b64 = new BASE64Decoder();
				byte[] decoded = b64.decodeBuffer(publicKeyPEM);
				X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
				pubKey = (RSAPublicKey) kf.generatePublic(spec);
			}
			//Initiate RSA Cipher
			cipher = Cipher.getInstance(CIPHER_MODE);

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * Encrypt with RSA(public key)
	 */
	public String encrypt(String plaintext) throws IOException {
		try{
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			int len = plaintext.length();
			StringBuffer cipherBuffer = new StringBuffer();
			int start = 0;
			int end = 0;
			while (start < len) {
				// calculate end index
				end = start + MAX_CIPHER_BLOCK_LEN - PADING_LEN;
				if (end > len) {
					end = len;
				}
				// encrypt a block data
				byte[] cipher_block = cipher.doFinal(((String) plaintext
						.substring(start, end)).getBytes());
				cipherBuffer.append(DatatypeConverter
						.printHexBinary(cipher_block));
				// calculate start index
				start = end;
			}
			return cipherBuffer.toString();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Decrypt with RSA(private key)
	 */
	public String decrypt(String ciphertext) throws IOException {
		try{
			cipher.init(Cipher.DECRYPT_MODE, privKey);
			int len = ciphertext.length();
			StringBuffer buffer = new StringBuffer();
			int start = 0;
			int end = 0;
			while(start < len){
				// calculate end index
				end = start + 2*MAX_CIPHER_BLOCK_LEN;
				if (end > len) {
					end = len;
				}
				// decrypt a block text
				byte[] block = cipher.doFinal(DatatypeConverter.parseHexBinary(ciphertext.substring(start, end)));
				buffer.append(new String(block));
				// calculate start index
				start = end;
			}
			return buffer.toString();
			
		}catch(Exception e){
			e.printStackTrace();
		}
		return null;
	}
	
    /**
     * Convert PKCS#1 encoded private key into RSAPrivateCrtKeySpec.
     * 
     * <p/>The ASN.1 syntax for the private key with CRT is
     * 
     * <pre>
     * -- 
     * -- Representation of RSA private key with information for the CRT algorithm.
     * --
	 * RSAPrivateKey ::= SEQUENCE {
     *   version           Version, 
     *   modulus           INTEGER,  -- n
     *   publicExponent    INTEGER,  -- e
     *   privateExponent   INTEGER,  -- d
     *   prime1            INTEGER,  -- p
     *   prime2            INTEGER,  -- q
     *   exponent1         INTEGER,  -- d mod (p-1)
     *   exponent2         INTEGER,  -- d mod (q-1) 
     *   coefficient       INTEGER,  -- (inverse of q) mod p
     *   otherPrimeInfos   OtherPrimeInfos OPTIONAL 
     * }
     * </pre>
     * 
     * @param keyBytes PKCS#1 encoded key
     * @return KeySpec
     * @throws IOException
     */
 
    private RSAPrivateCrtKeySpec getRSAKeySpec(byte[] keyBytes) throws IOException  {
    	
    	DerParser parser = new DerParser(keyBytes);
        
    	Asn1Object sequence = parser.read();
        if (sequence.getType() != DerParser.SEQUENCE)
        	throw new IOException("Invalid DER: not a sequence"); //$NON-NLS-1$
        
        // Parse inside the sequence
        parser = sequence.getParser();
        
        parser.read(); // Skip version
        BigInteger modulus = parser.read().getInteger();
        BigInteger publicExp = parser.read().getInteger();
        BigInteger privateExp = parser.read().getInteger();
        BigInteger prime1 = parser.read().getInteger();
        BigInteger prime2 = parser.read().getInteger();
        BigInteger exp1 = parser.read().getInteger();
        BigInteger exp2 = parser.read().getInteger();
        BigInteger crtCoef = parser.read().getInteger();
            
        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
        		modulus, publicExp, privateExp, prime1, prime2,
        		exp1, exp2, crtCoef);
        
        return keySpec;
    }  

}
