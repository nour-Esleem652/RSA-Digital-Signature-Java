package com.mycompany.rsa_digital_signature;

import java.security.*;
import java.util.Base64;

public class RSA_Digital_Signature {
    public static void main(String[] args) throws Exception {
        
        // 1. توليد مفاتيح RSA (Public & Private Keys)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        System.out.println("1. Key Pair Generated Successfully!");

        // 2. الرسالة الأصلية المراد توقيعها
        String originalMessage = "Transfer $1000 to Mark";
        System.out.println("2. Original Message: " + originalMessage);

        // 3. توقيع الرسالة باستخدام المفتاح الخاص (Private Key) مع SHA256withRSA
        Signature rsaSign = Signature.getInstance("SHA256withRSA");
        rsaSign.initSign(privateKey);
        rsaSign.update(originalMessage.getBytes());
        byte[] digitalSignature = rsaSign.sign();
        
        String signatureBase64 = Base64.getEncoder().encodeToString(digitalSignature);
        System.out.println("3. Digital Signature (Base64): " + signatureBase64.substring(0, 40) + "...");

        // 4. التحقق من صحة التوقيع باستخدام المفتاح العام (Public Key)
        Signature rsaVerify = Signature.getInstance("SHA256withRSA");
        rsaVerify.initVerify(publicKey);
        rsaVerify.update(originalMessage.getBytes());
        boolean isCorrect = rsaVerify.verify(digitalSignature);
        System.out.println("4. Verification Result for Original Message: " + (isCorrect ? "VALID (Success)" : "INVALID"));

        // 5. تجربة كشف التغيير (Tampering) لتعديل الرسالة
        String tamperedMessage = "Transfer $1000 to Oscar";
        System.out.println("\n--- Testing Tampered Message ---");
        System.out.println("Tampered Message: " + tamperedMessage);

        rsaVerify.update(tamperedMessage.getBytes());
        boolean isTamperedCorrect = rsaVerify.verify(digitalSignature);
        System.out.println("5. Verification Result for Tampered Message: " + (isTamperedCorrect ? "VALID" : "INVALID (Tampering Detected!)"));
    }
}

