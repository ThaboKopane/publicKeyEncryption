package publicKeyEncryption;


import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
/**
 * 
 * @author thadishi
 *A class that uses bouncy castle
 *Generates public key to encrypt shared keys
 */
public class rsaGenerator {
	
	private Cipher keyCipher;
	private Cipher keyDecipher;
	
	
	
	static Key publicKey, privateKey;
	
	/**
	 * A constructor that calls init()
	 * Init initialises the boucycastle security provider
	 */
	public rsaGenerator() {
		init();
	}
	public static void init() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	/*
	 * Generate a public key and a private key using the RSA algorith
	 * Store the keys into a file.
	 */
	
	public void generateRSAKey() throws NoSuchAlgorithmException, GeneralSecurityException, IOException{
		
		//useBuilt 
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		
		keyGen.initialize(1024);
		KeyPair keyPair = keyGen.generateKeyPair();
		
		//Generate the public key using the keyPair generator
		publicKey = keyPair.getPublic();
		System.out.println(publicKey);
		
		
		//~Generate teh private key using the key pair generator
		privateKey = keyPair.getPrivate();
		System.out.println(privateKey);
		
		//Use RSAKeySPec to 
		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pub = fact.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
		RSAPrivateKeySpec priv = fact.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);
		
		
		//Save keeys to the file system
		try {
		saveKeysToFile("public.key", pub.getModulus(), pub.getPublicExponent());
		saveKeysToFile("private.key", priv.getModulus(), priv.getPrivateExponent());
		} catch (Exception e) {
			throw new IOException("Error again", e);
		}
		
		
	}
	
	/**
	 * 
	 * @param filename name of keys to save files as
	 * @param mod biginteger and exponents, savinf keys this way
	 * @param exp
	 * @throws Exception
	 */
	public void saveKeysToFile(String filename, BigInteger mod, BigInteger exp) throws Exception{
		ObjectOutputStream ObjectOut = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
		
		try {
			ObjectOut.writeObject(mod);
			
			ObjectOut.writeObject(exp);
			System.out.println("Key File Created: "+ filename);
		} catch (Exception e) {
			throw new IOException("Error while writing the key object",e);
		} finally {
			ObjectOut.close();
		}
	}
	
	
	//A method to read the saved RSA keys from the file system
	PublicKey readPublicKeyFromFile(String fileName) throws IOException{
		
		FileInputStream in = new FileInputStream(fileName);
		ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
		PublicKey pubK = null;
		
		
		try {
			BigInteger m = (BigInteger) oin.readObject();
			BigInteger e = (BigInteger) oin.readObject();
			
			RSAPublicKeySpec keySpecifications = new RSAPublicKeySpec(m,e);
			
			KeyFactory kF = KeyFactory.getInstance("RSA");
			pubK = kF.generatePublic(keySpecifications);
			
		} catch(Exception e) {
			e.printStackTrace();
		} finally {
			oin.close();
		}
		return pubK;
	}
	
	//A method to read the private key from the ssyetm
	PrivateKey readPrivateKeyFromFile(String fileName) throws IOException{
		FileInputStream in = new FileInputStream(fileName);
	  	ObjectInputStream readObj =  new ObjectInputStream(new BufferedInputStream(in));
	  	PrivateKey priKey = null;
	  	
	  	try {
	  		BigInteger m = (BigInteger) readObj.readObject();
		  	  BigInteger d = (BigInteger) readObj.readObject();
		  	  RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, d);
		  	  KeyFactory fact = KeyFactory.getInstance("RSA");
		  	  priKey = fact.generatePrivate(keySpec);
	  	} catch (Exception e) {
	  		e.printStackTrace();
	  	} finally {
	  		readObj.close();
	  	}
	  	
	  	return priKey;
	}
	
	//A method to generate the shared AES key
	SecretKey generateSharedKey() throws NoSuchAlgorithmException{
		SecretKey AESkey = null;
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		AESkey = keyGen.generateKey();
		
		return AESkey;
	}
	
	//A method to encrypt the shared key
	public byte[] encryptSharedKey(SecretKey aesKey) throws Exception{
		keyCipher = null;
		byte[] key = null;
		
		//The Secrete AES key
		aesKey = generateSharedKey();
		try {
			PublicKey puKey = readPublicKeyFromFile("public.key");
			
			keyCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			keyCipher.init(Cipher.ENCRYPT_MODE, puKey);
			
			key = keyCipher.doFinal(aesKey.getEncoded());
		} catch (Exception e ) {
			e.printStackTrace();
		}
		return key; //the encrypted AES key
	}
	
	
	//A method to decrypt the shared key
	public SecretKey decryptSharedKey(byte[] encryptedKey) throws Exception{
		SecretKey aesKey = null;
		keyDecipher = null;
		
		try {
			PrivateKey prKey = readPrivateKeyFromFile("private.key");
			keyDecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			keyDecipher.init(Cipher.DECRYPT_MODE, prKey);
		

			aesKey = new SecretKeySpec(keyDecipher.doFinal(encryptedKey), "AES");
			
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		return aesKey;
		
	}
	
	
	public static void main(String[] args) {
		
		
		
		rsaGenerator RSA = new rsaGenerator();
		
		
		System.out.println("Save keys to file");
		
		try {
		//RSA.generateRSAKey();
		
		
		System.out.println("Encryption algorithm");
		SecretKey thabo_AES_key = RSA.generateSharedKey();
		byte[] keyJudas = RSA.encryptSharedKey(thabo_AES_key);
		System.out.println("The encrypeted shared key: "+ keyJudas);
		
		System.out.println("The decrypted shared key: "+ RSA.decryptSharedKey(keyJudas));
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		System.out.println("shit is gesund very sehr gesund");
	}
	

}
