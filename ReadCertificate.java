
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;

import javax.crypto.Cipher;


public class ReadCertificate {
	
	public static final String algorithm="RSA";
	public static final String text_to_be_encrypted="My name is Omkar Totade.";
	
	public static void main (String args[])
	{
			Certificate Raghucertificate=null;
			Certificate CAcertificate=null;
			X509Certificate tR=null;
			X509Certificate tCA=null;
			String home=System.getProperty("user.home");
			String Raghucert=home+"/Raghupub.cer";
			String Trustcentercert=home+"/Trustcenter.cer";
			String Raghupri=home+"/Raghupri.pfx";
			char[] password="raghu".toCharArray();
			KeyStore ks=null;
			try
			{
				FileInputStream fis1=new FileInputStream (Raghucert);
				FileInputStream fis2=new FileInputStream (Trustcentercert);
				FileInputStream fis3=new FileInputStream (Raghupri);
				CertificateFactory cf=CertificateFactory.getInstance ("X.509");
				Raghucertificate=cf.generateCertificate(fis1);
				CAcertificate=cf.generateCertificate(fis2);
				tR= (X509Certificate) Raghucertificate;
				tCA= (X509Certificate) CAcertificate;
				ks=KeyStore.getInstance("PKCS12");
				ks.load(fis3, password);
				
				
				fis1.close();
				fis2.close();
			}
			catch (Exception e)
			{
				System.out.println(e);
			}
			
			verify (Raghucertificate, CAcertificate);		//verify Raghu's certificate
			Raghu_printCertificate(Raghucertificate);		//print Raghu's certificate
			Raghu_printPublicKey(Raghucertificate); 		//print Raghu's public key
			//CA_printCertificate(CAcertificate);			//print CA's certificate
			displayRaghuPrivateKey(ks,password);			//print Raghu's private key	
			CA_printPublicKey(CAcertificate); 				//print CA's public key		
			Raghu_printSignature(tR);						//print signature on Raghu's certificate
			generateKeysForEncryption();					//generate keys and perform encryption and decryption
			
			
	}
	
	public static void verify (Certificate Raghucertificate, Certificate CAcertificate)
	{
		try
		{
			System.out.println("----------------------------------------------------------------------Raghu's Certificate Verification Start--------------------------------------------------------------------------------");
			System.out.println();
			
			//verifying Raghu's certificate
			Raghucertificate.verify(CAcertificate.getPublicKey());
			//verifying Raghu's certificate
			
			System.out.println("Raghu's Certificate is Verified");
			System.out.println("----------------------------------------------------------------------Raghu's Certificate Verification End--------------------------------------------------------------------------------");
			System.out.println();
			System.out.println();
			System.out.println();
		}
		catch(Exception e)
		{
			System.out.println(e);
		}
	}
	
	public static void displayRaghuPrivateKey (KeyStore ks, char[] password)
	{
		PrivateKey privateKey=null;
		try
		{
			String alias=(String) ks.aliases().nextElement();
			privateKey=(PrivateKey)ks.getKey(alias, password);
		}
		catch(Exception e)
		{
			System.out.println(e);
		}
		System.out.println("----------------------------------------------------------------------Raghu's Private Key Start--------------------------------------------------------------------------------");
		System.out.println();
		System.out.println("Raghu's Private Key:"+privateKey.toString());
		System.out.println();
		System.out.println("----------------------------------------------------------------------Raghu's Private Key End------------------------------------------------------------------------------------");
		System.out.println();
		System.out.println();
		System.out.println();
	}
	
	public static void Raghu_printCertificate (Certificate cert)
	{		
		System.out.println("----------------------------------------------------------------------Raghu's Certificate: Start--------------------------------------------------------------------------------");
		System.out.println(cert.toString());
		System.out.println("----------------------------------------------------------------------Raghu's Certificate End----------------------------------------------------------------------------------");
		System.out.println();
		System.out.println();
		System.out.println();		
	}
	
	public static void Raghu_printSignature (X509Certificate tR)
	{
		byte[] signature=tR.getSignature();
		System.out.println("----------------------------------------------------------------------Signature on Raghu's Certificate Start--------------------------------------------------------------------------------");
		System.out.println();
		System.out.println("Singature on Raghu's certificate="+new BigInteger(signature).toString(16));
		System.out.println();
		System.out.println("----------------------------------------------------------------------Signature on Raghu's Certificate End----------------------------------------------------------------------------------");
		System.out.println();
		System.out.println();
		System.out.println();
	}
	
	public static void CA_printCertificate (Certificate cert)
	{			
			System.out.println("----------------------------------------------------------------------CA Certificate Start--------------------------------------------------------------------------------");
			System.out.println(cert.toString());
			System.out.println("----------------------------------------------------------------------CA Certificate End----------------------------------------------------------------------------------");
			System.out.println();
			System.out.println();
			System.out.println();
	}
	
	public static void Raghu_printPublicKey (Certificate cert)
	{
		PublicKey pubKey=cert.getPublicKey();
		System.out.println("----------------------------------------------------------------------Raghu's Public Key Start--------------------------------------------------------------------------------");
		System.out.println(pubKey.toString());
		System.out.println("----------------------------------------------------------------------Raghu's Public Key End----------------------------------------------------------------------------------");
		System.out.println();
		System.out.println();
		System.out.println();
		//verify(cert, pubKey);
	}
	
	public static void CA_printPublicKey (Certificate cert)
	{
		PublicKey pubKey=cert.getPublicKey();
		System.out.println("----------------------------------------------------------------------CA's Public Key Start--------------------------------------------------------------------------------");
		System.out.println(pubKey.toString());
		System.out.println("----------------------------------------------------------------------CA's Public Key End----------------------------------------------------------------------------------");
		System.out.println();
		System.out.println();
		System.out.println();
	}
	
	public static void generateKeysForEncryption ()
	{
		byte [] ciphertext;
		String home=System.getProperty("user.home");
		String privateKeyFile=home+"/private.key";
		String publicKeyFile=home+"/public.key";
	
		try
		{
			final KeyPairGenerator kg=KeyPairGenerator.getInstance(algorithm);
			kg.initialize(1024);
			final KeyPair key=kg.generateKeyPair();
			
			File private_key_file=new File(privateKeyFile);
			File public_key_file=new File(publicKeyFile);
			
			//writing private and public keys to files
			
			ObjectOutputStream publicKeyObject=new ObjectOutputStream(new FileOutputStream(public_key_file));
			publicKeyObject.writeObject(key.getPublic());
			
			ObjectOutputStream privateKeyObject=new ObjectOutputStream(new FileOutputStream(private_key_file));
			privateKeyObject.writeObject(key.getPrivate());
			
			publicKeyObject.close();
			privateKeyObject.close();
			
			PrivateKey private_key=key.getPrivate();
			PublicKey public_key=key.getPublic();
			
			ciphertext=encrypt (private_key);							//encrypt using private key
			String dec_plaintext= decrypt (ciphertext, public_key);		//decrypt using public key
			
			System.out.println("----------------------------------------------------------------------RSA Encryption and Decryption Start--------------------------------------------------------------------------------");
			System.out.println();
			System.out.println("Private Key Used="+private_key);
			System.out.println();
			System.out.println("Public Key Used="+public_key);
			System.out.println();
			System.out.println("Text to be encrypted="+text_to_be_encrypted);
			System.out.println();
			System.out.println("Ciphertext obtained="+new String(ciphertext));
			System.out.println();
			System.out.println("Decrypted Plaintext="+dec_plaintext);
			System.out.println();
			System.out.println("----------------------------------------------------------------------RSA Encryption and Decryption End----------------------------------------------------------------------------------");
			System.out.println();
			System.out.println();
			System.out.println();
			
		}
		catch (Exception e)
		{
			System.out.println(e);
		}
	}
	
	public static byte[] encrypt (PrivateKey private_key)
	{
		byte[] ciphertext=null;
		
		try
		{
			final Cipher cipher=Cipher.getInstance(algorithm);
			cipher.init(Cipher.ENCRYPT_MODE, private_key);
			ciphertext=cipher.doFinal(text_to_be_encrypted.getBytes());
		}
		catch(Exception e)
		{
			System.out.println(e);
		}
		
		return ciphertext;
	}
	
	
	public static String decrypt (byte[] ciphertext, PublicKey public_key)
	{
		String plaintext="";
		byte[] decrypted_text=null;
		
		try
		{
			final Cipher cipher=Cipher.getInstance(algorithm);
			cipher.init(Cipher.DECRYPT_MODE, public_key);
			decrypted_text=cipher.doFinal(ciphertext);
		}
		catch(Exception e)
		{
			System.out.println(e);
		}
		
		plaintext=new String (decrypted_text);
		return plaintext;
	}
}