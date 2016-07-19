import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class DES implements CipherInterface {
	
	private static final String TAG = "DES";
	private final String CIPHER_MODE = "DES/ECB/PKCS5Padding";//Block Cipher Mode
	private Cipher desCipher;// DES Cipher
	private SecretKey desKey;// DES Key

	/**
	 * Set DES Key
	 */
	public void setKey(String key) throws InvalidKeyException, InvalidKeySpecException {
		
	    byte[] data = Base64.getDecoder().decode(key.getBytes());
	    desKey = new SecretKeySpec(data, 0, data.length, "DES");
	    /* Create an instance of the DES cipher */

		try {
			desCipher = Cipher.getInstance(CIPHER_MODE);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	    
//		SecretKeyFactory secretKeyFactory;
//		try {
//			//create DES Key
//			secretKeyFactory = SecretKeyFactory.getInstance("DES");
//			desKey = secretKeyFactory.generateSecret(new DESKeySpec(key.getBytes()));
//		    /* Create an instance of the DES cipher */
//		    try {
//				desCipher = Cipher.getInstance(CIPHER_MODE);
//			} catch (NoSuchPaddingException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//		
//		} catch (NoSuchAlgorithmException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
	}

	/**
	 * Encrypt plain text with DES
	 */
	public String encrypt(String plaintext) throws IOException {
		try{
	    	 /* Initialize the cipher for encryption. */
			desCipher.init(Cipher.ENCRYPT_MODE, desKey);
			 /* Encrypt the text */
			byte[] textEncrypted = desCipher.doFinal(plaintext.getBytes());
			String cipherText = new String(textEncrypted);
			return cipherText;
		}catch (Exception e){
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Decrypt cipher text with DES
	 */
	public String decrypt(String ciphertext) throws IOException {
		try{
			/* Initialize the same cipher for decryption. */
		    desCipher.init(Cipher.DECRYPT_MODE, desKey);
		    /* Decrypt the text */
		    byte[] textDecrypted = desCipher.doFinal(ciphertext.getBytes());
		    String decryptionText = new String(textDecrypted);
		    return decryptionText;
		}catch (Exception e){
			e.printStackTrace();
		}
		return null;
	}
}
