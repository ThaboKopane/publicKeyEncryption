package publicKeyEncryption;


import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class rsaGenerator {
	
	private Cipher keyCipher;
	private Cipher keyDecipher;
	
	
	SecretKey AESkey;
	static Key publicKey, privateKey;
	
	public rsaGenerator() {
		init();
	}
	public static void init() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	/*
	 * Generate a public private key
	 */
	
	public void generateRSAKey() throws NoSuchAlgorithmException, GeneralSecurityException, IOException{
		
		//useBuilt 
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		
		keyGen.initialize(1024);
		
		KeyPair keyPair = keyGen.generateKeyPair();
		publicKey = keyPair.getPublic();
		System.out.println(publicKey);
		
		
		//Make sure teh 
		
		privateKey = keyPair.getPrivate();
		System.out.println(privateKey);
		
		//output the keys
		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pub = fact.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
		RSAPrivateKeySpec priv = fact.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);
		
		try {
		saveKeysToFile("public.key", pub.getModulus(), pub.getPublicExponent());
		saveKeysToFile("private.key", priv.getModulus(), priv.getPrivateExponent());
		} catch (Exception e) {
			throw new IOException("Error again", e);
		}
		
		
	}
	
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
	
	void generateSharedKey() throws NoSuchAlgorithmException{
		AESkey = null;
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		AESkey = keyGen.generateKey();
	}
	
	public byte[] encryptSharedKey() throws Exception{
		keyCipher = null;
		byte[] key = null;
		try {
			PublicKey puKey = readPublicKeyFromFile("public.key");
			
			keyCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			keyCipher.init(Cipher.ENCRYPT_MODE, puKey);
			
			key = keyCipher.doFinal(AESkey.getEncoded());
		} catch (Exception e ) {
			e.printStackTrace();
		}
		return key; //the encrypted AES key
	}
	
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
		
		System.out.println("shit hit the fan");
		
		rsaGenerator RSA = new rsaGenerator();
		
		
		System.out.println("Save keys to file");
		
		try {
		//RSA.generateRSAKey();
		
		
		System.out.println("Encryption algorithm");
		RSA.generateSharedKey();
		byte[] keyJudas = RSA.encryptSharedKey();
		System.out.println("The encrypeted shared key: "+ keyJudas);
		
		System.out.println("The decrypted shared key: "+ RSA.decryptSharedKey(keyJudas));
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		/*try {
		System.out.println(generateRSAKey());
		} catch (Exception ex) {
			ex.printStackTrace();
		}*/
	}
	

}
