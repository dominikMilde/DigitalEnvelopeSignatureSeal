package hr.fer.zemris.kik.asymmetry;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;

import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Main {

    private static String fileName = "Files/data";
    public static void main(String[] args) {
        keyGenerate(2048);

        //sign("SHA256withRSA", "Files/signature");
        //verify("SHA256withRSA", "Files/signature");

        //encodeEnvelope("AES", 192, "AES/CBC/PKCS5Padding");
        //decryptEnvelope("AES" ,"AES/CBC/PKCS5Padding");

        seal("AES", 192, "AES/CBC/PKCS5Padding", "SHA256withRSA");
        unSeal("AES", 192, "AES/CBC/PKCS5Padding", "SHA256withRSA");
    }

    private static void sign(String option, String destinationName){
        try{
            File priv = new File("KeyPair/privateKey");
            FileInputStream inPriv = new FileInputStream(priv);
            byte[] privateKeyBytesBase = new byte[(int) priv.length()];
            inPriv.read(privateKeyBytesBase);
            inPriv.close();

            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBytesBase);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privKey = keyFactory.generatePrivate(privateKeySpec);

            Signature signature = Signature.getInstance(option);
            signature.initSign(privKey);

            File file = new File(fileName);
            FileInputStream in = new FileInputStream(file);
            byte[] message = new byte[(int) file.length()];
            in.read(message);
            in.close();
            signature.update(message);

            byte[] sigBytesBase = signature.sign();
            //System.out.println(new String(sigBytesBase));

            byte[] sigBytes = Base64.getEncoder().encode(sigBytesBase);
            FileOutputStream out = new FileOutputStream(destinationName);
            out.write(sigBytes);
            out.close();

        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private static void verify(String option, String destinationName){
        File filePublic = new File("KeyPair/publicKey");
        File fileSig = new File(destinationName);
        try {
            File file = new File(fileName);
            FileInputStream inPublic = new FileInputStream(filePublic);
            byte[] publicKeyBytesBase = new byte[(int) filePublic.length()];
            inPublic.read(publicKeyBytesBase);
            inPublic.close();

            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBytesBase);

            FileInputStream in = new FileInputStream(file);
            byte[] message = new byte[(int) file.length()];
            in.read(message);
            in.close();
            FileInputStream inSig = new FileInputStream(fileSig);
            byte[] sigBytesBase = new byte[(int) fileSig.length()];
            inSig.read(sigBytesBase);
            inSig.close();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            byte[] sigBytes = Base64.getDecoder().decode(sigBytesBase);
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
            Signature signature = Signature.getInstance(option);
            signature.initVerify(pubKey);
            signature.update(message);
            if(signature.verify(sigBytes)){
                System.out.println("Digitalni potpis je ISPRAVAN!");
            }
            else{
                System.out.println("Digitalni potpis NIJE ispravan!");
            }

        } catch (Exception e1) {
            System.out.println("GREŠKA Digitalni potpis nije ispravan!");
        }
    }

    private static void encodeEnvelope(String algorithm, int keySize, String option) {
        try {
            File filePublic = new File("KeyPair/publicKey");

            File file = new File(fileName);
            FileInputStream in = new FileInputStream(file);
            byte[] message = new byte[(int) file.length()];
            in.read(message);
            in.close();

            byte[] iv;
            if(algorithm.equals("AES")){
                iv = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7};
            }
            else{
                iv = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
            }

            IvParameterSpec ivspec = new IvParameterSpec(iv);


            KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
            keyGenerator.init(keySize);
            SecretKey key = keyGenerator.generateKey();


            Cipher cipher = Cipher.getInstance(option);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);

            byte[] cipherText = cipher.doFinal(message);
            byte[] keyCoded = key.getEncoded();

            System.out.println("Ključ prije kriptiranja:");
            System.out.println(new String(keyCoded));

            FileInputStream inPublic = new FileInputStream(filePublic);
            byte[] publicKeyBytesBase = new byte[(int) filePublic.length()];
            inPublic.read(publicKeyBytesBase);
            inPublic.close();

            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBytesBase);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);

            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] encryptedMessageBytes = encryptCipher.doFinal(keyCoded);

            FileOutputStream out = new FileOutputStream("Files/envelopeCryptKey");
            out.write(Base64.getEncoder().encode(encryptedMessageBytes));
            out.close();

            FileOutputStream outS = new FileOutputStream("Files/envelopeData");
            outS.write(Base64.getEncoder().encode(cipherText));
            outS.close();

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    private static void decryptEnvelope(String algorithm, String option){
        try{
            File file = new File("Files/envelopeCryptKey");
            FileInputStream in = new FileInputStream(file);
            byte[] part = new byte[(int) file.length()];
            in.read(part);
            in.close();

            File priv = new File("KeyPair/privateKey");
            FileInputStream inPriv = new FileInputStream(priv);
            byte[] privateKeyBytesBase = new byte[(int) priv.length()];
            inPriv.read(privateKeyBytesBase);
            inPriv.close();

            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBytesBase);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privKey = keyFactory.generatePrivate(privateKeySpec);


            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, privKey);

            byte[] keyCoded = decryptCipher.doFinal(Base64.getDecoder().decode(part));
            System.out.println("Dekriptirani ključ:");
            System.out.println(new String(keyCoded));
            SecretKey originalKey = new SecretKeySpec(keyCoded, 0, keyCoded.length, algorithm);

            byte[] iv;
            if(algorithm.equals("AES")){
                iv = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7};
            }
            else{
                iv = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
            }
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance(option);
            cipher.init(Cipher.DECRYPT_MODE, originalKey, ivspec);

            File file1 = new File("Files/envelopeData");
            FileInputStream in1 = new FileInputStream(file1);
            byte[] part1 = new byte[(int) file1.length()];
            in1.read(part1);
            in1.close();



            byte[] plain = cipher.doFinal(Base64.getDecoder().decode(part1));
            System.out.println("Poruka:");
            System.out.println(new String(plain));

        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    private static void seal(String alg, int n, String option, String hashOpt){
        encodeEnvelope(alg, n, option);
        fileName = "Files/envelopeData";
        sign(hashOpt, "Files/sealEnvData");
        fileName = "Files/envelopeCryptKey";
        sign(hashOpt, "Files/sealEnvCryptKey");
    }

    private static void unSeal(String alg, int n, String option, String hashOpt){
        fileName = "Files/envelopeData";
        verify(hashOpt, "Files/sealEnvData");
        fileName = "Files/envelopeCryptKey";
        verify(hashOpt, "Files/sealEnvCryptKey");
        fileName = "Files/data";
        decryptEnvelope(alg, option);
    }

    private static void keyGenerate(int n){
        GenerateKeys gk;
        try {
            gk = new GenerateKeys(n);
            gk.createKeys();
            gk.writeToFile("KeyPair/publicKey", Base64.getEncoder().encode(gk.getPublicKey().getEncoded()));
            gk.writeToFile("KeyPair/privateKey", Base64.getEncoder().encode(gk.getPrivateKey().getEncoded()));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | IOException e) {
            System.err.println(e.getMessage());
        }
    }
}
