

/**
* The Program will provide Hybrid Encryption Scheme
* 
*
* @author  SUBHABRATA RANA
* @version 1.0
* @since   2022-10-14
* @assignment : 01 
*/
import java.util.*;
import java.math.*;
import java.security.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import java.io.File; 
import java.io.IOException; 
import java.io.RandomAccessFile;
import java.io.FileOutputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.security.SecureRandom;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;



public class HybridCryptographyModule 
{
	private static HashMap<Character, BigInteger> private_public_Params=new HashMap<Character,BigInteger>();
	public static int numberOfBytesIn1MB=1000000;
	public static int aesSecurityInBit=128;
    public static String algorithmName="AES";
	
	
	public static void main(String[] args) 
	{
		
       byte[] plaintext_inBytes=new byte[numberOfBytesIn1MB];
       HashMap<Character,BigInteger> publicKeyStore_FromAlice=new HashMap<Character,BigInteger>();
	
		 try
		 {
			 // STEP 1: Generate the 1 MB data
		     plaintext_inBytes=GenerateDataInBytes();
			 
			 // STEP 2: Generate a AES Key							 
		     SecretKey aesKey_inSecretKey=getVerifiedAESKey();
		     byte[] aeskey_Bytes = aesKey_inSecretKey.getEncoded();
		     		
			 String encodedKey = Base64.getEncoder().encodeToString(aeskey_Bytes);
			 byte[] decodedKey = Base64.getDecoder().decode(encodedKey);	
			 
			  		      
		      // SIGN MANITURE REPRESENTATION OF BIG INTEGER
	          String aesKeyToHex_Base64 = String.format("%032x", new BigInteger(1, decodedKey));	 
	          
		      System.out.println("The AES key in hex K: "+aesKeyToHex_Base64);
		      System.out.println("-------------------------------------------------------------------------------");
		        //Converting aesKey that is generated to BigInteger
	            BigInteger aesKeyToBigInteger = new BigInteger(aesKeyToHex_Base64,  16);
	            
	   
			 
	           
			 //--------------------------------------------------------------------------------			  	  
			  // Encrypt the plaintext using AES,Remember all data must be encrypted		
			   String [] plaintext_InHexFormat=convertPlaintextToHexadecimal(plaintext_inBytes,numberOfBytesIn1MB);  
			   System.out.println("-------------------------------------------------------------------------------");
			   
			   String cipherText;
			   String [] cipherTextStore=new String[numberOfBytesIn1MB];	
			   System.out.println("First 32 bytes of C_aes (Note: The ciphertexts are encoded with Base 64) :\n");		
			  for(int i=0;i<numberOfBytesIn1MB;i++)
			  {			   
				  byte[] cipherText_RSA = encryptText(plaintext_InHexFormat[i], aesKey_inSecretKey);			
				  cipherText=Base64.getEncoder().encodeToString(cipherText_RSA);			    
			      cipherTextStore[i]=cipherText;
			      if((i>=0)&&(i<32))
			      {
			    	  System.out.println("Ciphertext ["+i +" ] : "+cipherTextStore[i]);
			      }
			  }
					  
			    //  Get the public key parameters
			     publicKeyStore_FromAlice=getPublicKey_From_Alice();					 
				
			      // Call Bob to encrypt the Bob's AES key using Alice's Public Key 
				  System.out.println("-------------------------------------------------------------------------------\n");
		   		BigInteger encryptedAESKey=getEncryptedAESKey(aesKeyToBigInteger,publicKeyStore_FromAlice);
		   		System.out.print("Encrypted AES Key, C_rsa : "+encryptedAESKey);
		  	   System.out.println("\n-------------------------------------------------------------------------------\n");
		  	  
				// Send the Encrypted Data and Encrypted Key to Alice for Decryption
	    		sendEncryptedAESKey_And_EncryptedData_To_Alice(encryptedAESKey, cipherTextStore); 
						  
			 
		 }
		catch(Exception ex)
		 {
			System.out.println("Encryption occures while generating random number:"+ex);
		 }

		
	}// main
	
	
	 private static SecretKey getVerifiedAESKey()
	{
		 byte[] aeskey_Bytes=new byte[16];
		 Integer unsignedFirstByte_InInt=0;
		  SecretKey aesKey_inSecretKey;
	
			do
			{
				 aesKey_inSecretKey=getAESSecretKey(aesSecurityInBit);
				 aeskey_Bytes = aesKey_inSecretKey.getEncoded();			
				unsignedFirstByte_InInt=Byte.toUnsignedInt(aeskey_Bytes[0]);
			}while(unsignedFirstByte_InInt>127);
		return aesKey_inSecretKey;
	}
	

    private static byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }
	

	// This will generate Bytes Random Numbers
	private static byte[] GenerateDataInBytes()
	{
		byte[] byteArray=new byte[numberOfBytesIn1MB];
		String[] byteArrayHexDecimal=new String[numberOfBytesIn1MB];
		
		try
		{
			  Random rd = new Random();		      
		      rd.nextBytes(byteArray);
		      for(int i=0;i<numberOfBytesIn1MB;i++)
		      {
		    	     int hex = byteArray[i] & 0xFF;
		    	     byteArrayHexDecimal[i]=Integer.toHexString(hex);
		    
		      }
		}
		catch(Exception e)
		{
			System.out.println("An error occurred while generating the bytearray.");
		    e.printStackTrace();
		}
		return byteArray;
	}
	

	
	// This function generates AES Secret Key
	   public static SecretKey getAESSecretKey(int aesSecurityInBit) {
		   KeyGenerator keyGen = null;
		   try
		   {
			    keyGen = KeyGenerator.getInstance("AES");
		        keyGen.init(aesSecurityInBit, SecureRandom.getInstanceStrong()); 
		   }
		   catch(NoSuchAlgorithmException ex)
		   {
			   ex.printStackTrace();
		   }
		   
		     /* Generates a secret key */
		      SecretKey secretKey = keyGen.generateKey();
		   return secretKey;
	   }
	    
	   	
	
	//This will convert the AES key in HEX format
	private static String[] convertPlaintextToHexadecimal(byte[] dataBytes, int dataLength)
	{
		String[] byteArrayHex=new String[dataLength];		
		try
		{
			 System.out.print("\nFirst 32 bytes of M: \n");
			  for(int i=0;i<dataLength;i++)
		      {
				  
		    	    int hex = dataBytes[i] & 0xFF;
		    	    byteArrayHex[i]=Integer.toHexString(hex);
		    	    if(i>=0 && i<32)
		    	    {
		    	    	 System.out.print(byteArrayHex[i]+"\t");	
		    	    }
		      }
			  System.out.println("\n");
		}
		catch(Exception ex) 
		{
			 System.out.println("An error occurred while converting  AES Key to Hex : "+ex);
			 ex.printStackTrace();
		}
		return byteArrayHex;
	}
	
	
					

    public static byte[] encryptText(String plainText,SecretKey secKey) throws Exception{
        // AES defaults to AES/ECB/PKCS5Padding in Java 7
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
            byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());
            return byteCipherText;
            
           // return Base64.getEncoder().encodeToString(byteCipherText);
        }

    

    
    public static String decryptText(byte[] byteCipherText, SecretKey secKey) throws Exception {
        // AES defaults to AES/ECB/PKCS5Padding in Java 7
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.DECRYPT_MODE, secKey);
            byte[] bytePlainText = aesCipher.doFinal(byteCipherText);
            return new String(bytePlainText);
        }
         
    
	
  
	// This function will create a public private key pair and will provide only the public key to the 
	private static HashMap<Character,BigInteger> getPublicKey_From_Alice()
	{
		HashMap<Character,BigInteger> publicKeyStore=new HashMap<Character,BigInteger>();
		
		try
		{
			// Alice gets the generates public-private key pairs from internal operation
			// but for outside world, she only provides the relevant information i.e. e and n
			private_public_Params=generatePrivatePublicKeyPair();
			BigInteger decryptionExponent=private_public_Params.get('d');
			BigInteger encryptionExponent=private_public_Params.get('e');
			BigInteger primeNumber1=private_public_Params.get('p');
			BigInteger primeNumber2=private_public_Params.get('q');
			BigInteger compositeModulus=private_public_Params.get('n');
			BigInteger fi_n=private_public_Params.get('f');
			
			// Just for testing purpose, in actual program comment them
			//System.out.println("The first prime is p: "+ primeNumber1);
			//System.out.println("The second prime is q: "+ primeNumber2);
			//System.out.println("The composite modulus n: "+ compositeModulus);
			//System.out.println("The encryption exponent e: "+ encryptionExponent);
			//System.out.println("The decryption exponent d: "+ decryptionExponent);
			//System.out.println("The Fi_N: "+ fi_n);
		
			// This function will return only the variables required for the message encryption using public key
			publicKeyStore.put('e', encryptionExponent);
			publicKeyStore.put('n', compositeModulus);
			
		}
		catch(Exception ex)
		{
			 System.out.println("Exception occurred while getting public key from Alice : " +ex);
		}
		return publicKeyStore;
		
	}
	

		
	// This function will provide encrypted AES key
	private static BigInteger getEncryptedAESKey(BigInteger aesKey_Biginteger, HashMap<Character,BigInteger>publicKeyStore_FromAlice)
	{
		
		BigInteger encryptedAESKey=BigInteger.ZERO;
		
		try
		{
			// Get the public keys from Bob
			BigInteger encryptionExponent_e_from_Bob=publicKeyStore_FromAlice.get('e');
			BigInteger compositeModulus_n_from_Bob=publicKeyStore_FromAlice.get('n');
			
			encryptedAESKey=aesKey_Biginteger.modPow(encryptionExponent_e_from_Bob,compositeModulus_n_from_Bob); 
		}
		catch(Exception ex)
		{
			 System.out.println("Exception occurred while getting encrypted key and message from Bob : " +ex);
		}
		
		return encryptedAESKey;
		
	}
	
	
	
	  // This function will return the private key set
	  private static HashMap<Character,BigInteger> generatePrivatePublicKeyPair()
	  {
		
		  HashMap<Character,BigInteger> privateKeyStore=new HashMap<Character,BigInteger>();
		  
		  // Prime Numbers are private
		  BigInteger primeNumber1=new BigInteger("19211916981990472618936322908621863986876987146317321175477459636156953561475008733870517275438245830106443145241548501528064000686696553079813968930084003413592173929258239545538559059522893001415540383237712787805857248668921475503029012210091798624401493551321836739170290569343885146402734119714622761918874473987849224658821203492683692059569546468953937059529709368583742816455260753650612502430591087268113652659115398868234585603351162620007030560547611");
		  BigInteger primeNumber2=new BigInteger("49400957163547757452528775346560420645353827504469813702447095057241998403355821905395551250978714023163401985077729384422721713135644084394023796644398582673187943364713315617271802772949577464712104737208148338528834981720321532125957782517699692081175107563795482281654333294693930543491780359799856300841301804870312412567636723373557700882499622073341225199446003974972311496703259471182056856143760293363135470539860065760306974196552067736902898897585691");
		  
		  
		//BigInteger primeNumber1=new BigInteger("11");
	    //BigInteger primeNumber2=new BigInteger("13");
		  
		  BigInteger encryptionExponent=BigInteger.ZERO;
		  try
		  {
			  // Composite Modulus
			  BigInteger compositeModulus=primeNumber1.multiply(primeNumber2);
			  
			  // Generate Fi(n)=(p-1) * (q-1)
			  BigInteger fi_n=(primeNumber1.subtract(BigInteger.ONE)).multiply(primeNumber2.subtract(BigInteger.ONE));
			  
			  encryptionExponent=getEncryptionExponant(fi_n);
					  
			  // Get the public Key
			  BigInteger  decryptionExponent = encryptionExponent.modInverse(fi_n);		
			  
			  //Store the values in to the hash map
			  privateKeyStore.put('d', decryptionExponent);
			  privateKeyStore.put('e', encryptionExponent);
			  privateKeyStore.put('p', primeNumber1);
			  privateKeyStore.put('q', primeNumber2);
			  privateKeyStore.put('n', compositeModulus); 
			  privateKeyStore.put('f', fi_n); 
			
		  }
		  catch(Exception ex)
		  {
			  System.out.println("Exception occurred while generating private key : " +ex);
		  }
		  
		  return privateKeyStore;
	  }
	
	  
	  // This function returns Encryption Exponent
     private static BigInteger getEncryptionExponant(BigInteger fi_N)
     {
    	 BigInteger exponent=BigInteger.ZERO;     
         BigInteger gcdValue=BigInteger.ZERO;
    	 try
    	 {
    		// gcdValue= exponent.gcd(fi_N);
    		 for (exponent = BigInteger.valueOf(2); exponent.compareTo(fi_N)==-1; exponent=exponent.add(BigInteger.ONE)) 
			   {
    			    
    			  gcdValue=exponent.gcd(fi_N);    	
				  if (gcdValue.compareTo(BigInteger.valueOf(1))==0)
				  {
		                break;
		          }
		     }
			   
    	 }
    	 catch(Exception ex)
    	 {
    		 System.out.println("Exception occurred while getiting exponent : "+ex);
    	 }
    
    	 return exponent;
     }
     


			    
    private static void  sendEncryptedAESKey_And_EncryptedData_To_Alice(BigInteger encryptedAESKey,String[] cipherTextStore)
		  {
    	   SecretKey aesKeyRecovery_OriginalKey_InSecretKeyFormat ;
			  try
			  {
				
				  
				  //System.out.println("-------------------------------------------------------------------------------\n");
				  BigInteger deceryptedAESKey=decryptAESKey_Using_RSAPrivateKey(encryptedAESKey);			
				  System.out.println("Decrypted key K: (BigInteger Format) "+deceryptedAESKey);
				  
				  
				  String encodedKey_Base64 = Base64.getEncoder().encodeToString(deceryptedAESKey.toByteArray());
				  byte[] decodedKey = Base64.getDecoder().decode(encodedKey_Base64);
					 
	  		      
			      // SIGN MANITURE REPRESENTATION OF BIG INTEGER
		          String aesKeyToHex_Base64 = String.format("%032x", new BigInteger(1, decodedKey));	
				  System.out.println("Decrypted key K: (In Hexadecimal Format) "+aesKeyToHex_Base64);
				 // String encodedMaxB64 = new String(Base64.Encoder(new BigInteger("4294967295")), StandardCharsets.UTF_8);
				  System.out.println("-------------------------------------------------------------------------------\n");
				  
				  
				  // Get the original Secret key from Big Integer
				  aesKeyRecovery_OriginalKey_InSecretKeyFormat = new SecretKeySpec(deceryptedAESKey.toByteArray(),0,(deceryptedAESKey.toByteArray()).length, "AES");
				  
				  System.out.println("Decrypted first 32 bytes of M: \n");
				   for(int i=0;i<numberOfBytesIn1MB;i++)
					  {  			      
							 byte[] aesDataRecovery_data_in_bytes = decode(cipherTextStore[i]);
							      
						      String decryptedText= decryptText(aesDataRecovery_data_in_bytes, aesKeyRecovery_OriginalKey_InSecretKeyFormat);
						      if( (i>=0)&& (i<32))
						      {
						    	  System.out.print(decryptedText+"\t");	
						    	  
							      // use below if you want to check the ciphertext-planintext format						      
								 // System.out.print(i+ "\t Encrypted : "+cipherTextStore[i] +"\tDecrypted\t" +decryptedText+"\n");	 
						      }
						      
						    			  
					  }
				   System.out.println("\n-------------------------------------------------------------------------------\n");
				  
		    }
			catch(Exception ex)
			  {
				  System.out.println("Exception occurred while sending Encrypted keys and Data : "+ex);
			  }
			  			  
		  }
		  
		 
	 
	  // Alice will use this function to decrypt RSA key received from BOB
	  // <return>Alice will return plaintext AES key <return>
	  private static BigInteger decryptAESKey_Using_RSAPrivateKey(BigInteger encryptedAESKey)
	  {		 
				
			BigInteger plaintextAESKey=BigInteger.ZERO;
		    BigInteger decryptionExponent=BigInteger.ZERO; 
		    BigInteger compositeModulus=BigInteger.ZERO; 
		  try
		  { 
			  decryptionExponent=private_public_Params.get('d');
			  compositeModulus=private_public_Params.get('n');
			  
			  //Convert ciphertext received from Bob
			  plaintextAESKey=encryptedAESKey.modPow(decryptionExponent,compositeModulus);			  			  
				
		  }
		  catch(Exception ex)
		  {
			  System.out.println("Exception occurred while decrypting key : "+ex);
		  }	
		  
		  return plaintextAESKey;
	  }
  	    
	  
//	
//		private static byte[] getByteArrayFromHexadecimalString(String hexCode)
//		{
//			 byte[] byteArray=new byte[hexCode.length() / 2];
//			try
//			{
//				 System.out.println("\n");
//				 byteArray = new byte[hexCode.length() / 2];
//				 for (int i = 0; i < byteArray.length; i++) {
//					   int index = i * 2;
//					   int j = Integer.parseInt(hexCode.substring(index, index + 2), 16);
//					   byteArray[i] = (byte) j;
//					   System.out.println( byteArray[i]);
//					}
//			}
//			catch(Exception ex)
//			{
//				 System.out.println("Exception occurred while decrypting key : "+ex);
//				
//			}
//			return byteArray;
//		}
//
//	
	
	
	
	
	
	
	// This function will create a file of 1  MB
//		private static File CreateFile(final String filename, final long sizeInBytes)
//		{
//			
//			 File file = new File(filename);
//			 try {
//			
//			      if (file.createNewFile())
//			      {
//			        //System.out.println("File created: " + file.getName());
//			      } 
//			      else 
//			      {
//			       // System.out.println("File already exists.");
//			      }
//			    
//			      RandomAccessFile raf = new RandomAccessFile(file, "rw");
//			      raf.setLength(sizeInBytes);
//			      raf.close();
//			    } 
//		   	  catch (IOException e) 
//			    {
//			
//			      System.out.println("An error occurred while creating the file.");
//			      e.printStackTrace();
//			    }
//			 return  file;
//			
//		}
	
	
	
	   
//	   private static String convertAESKeyToHexadecimal_OutputInArray_FromInteger(int[] keyBytes_IntInt, int AESKeyLength)
//		{
//			 String[] byteArrayHex=new String[AESKeyLength];
//			 StringBuilder aesKey_String = new StringBuilder();
//			try
//			{
//				  for(int i=0;i<AESKeyLength;i++)
//			      {
//			    	 
//			    	    byteArrayHex[i]=Integer.toHexString(keyBytes_IntInt[i]);
//			    	  
//			    	    aesKey_String.append(byteArrayHex[i].toString());
//			      }
//				  System.out.println("\n");
//			}
//			catch(Exception ex) 
//			{
//				 System.out.println("An error occurred while converting  AES Key to Hex."+ex);
//				 ex.printStackTrace();
//			}
//			return aesKey_String.toString();
//		}
//		
	   
	 
	
	
////This will convert the AES key in HEX format IN ARRAY FORMAT
//private static String[] convertAESKeyToHexadecimal_OutputInArray(byte[] keyBytes, int AESKeyLength)
//{
//	 String[] byteArrayHex=new String[AESKeyLength];		
//	try
//	{
//		  for(int i=0;i<AESKeyLength;i++)
//	      {
//	    	    int hex = keyBytes[i] & 0xFFFF;
//	    	    byteArrayHex[i]=Integer.toHexString(hex);
//	    	
//	      }
//		  System.out.println("\n");
//	}
//	catch(Exception ex) 
//	{
//		 System.out.println("An error occurred while converting  AES Key to Hex."+ex);
//		 ex.printStackTrace();
//	}
//	return byteArrayHex;
//}
//


//
////This will convert the AES key in HEX STRING format
//private static String convertAESKeyToHexadecimal_OutputInString(byte[] keyBytes, int AESKeyLength)
//{
//	 String[] byteArrayHex=new String[AESKeyLength];
//	 StringBuilder aesKey_String = new StringBuilder();
//	try
//	{
//		  for(int i=0;i<AESKeyLength;i++)
//	      {
//	    	    int hex = keyBytes[i] & 0xFF;
//	    	    byteArrayHex[i]=Integer.toHexString(hex);
//	    	    aesKey_String.append(byteArrayHex[i].toString());
//	    	
//	      }
//		  
//	}
//	catch(Exception ex) 
//	{
//		 System.out.println("An error occurred while converting  AES Key to Hex."+ex);
//		 ex.printStackTrace();
//	}
//	return aesKey_String.toString();
//}

	
}//class
