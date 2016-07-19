import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

/**
 * This class implements the interface for a typical cipher.
 * It defines functions usually used in a cipher
 */

public interface CipherInterface {
	
	/**
	 * Sets the key to use
	 * 
	 * @param key
	 *            - the key to use
	 * @return - True if the key is valid and False otherwise
	 * @throws InvalidKeySpecException 
	 * @throws InvalidKeyException 
	 */
	void setKey(String key) throws InvalidKeyException, InvalidKeySpecException;
	/**
	 * Encrypts a plaintext string
	 * 
	 * @param plaintext
	 *            - the plaintext string
	 * @return - the encrypted ciphertext string
	 * @throws IOException 
	 */
	String encrypt(String plaintext) throws IOException;

	/**
	 * Decrypts a string of ciphertext
	 * 
	 * @param ciphertext
	 *            - the ciphertext
	 * @return - the plaintext
	 * @throws IOException 
	 */
	String decrypt(String ciphertext) throws IOException;
		
}
