/**
 * Disclaimer: This code is for illustration purposes. Do not use in real-world deployments.
 */

public class PaddingOracleAttackSimulation_7058_Omar_Walid {

  private static class Sender {
    private byte[] secretKey;
    private String secretMessage = "Top secret!";

    public Sender(byte[] secretKey) {
      this.secretKey = secretKey;
    }

    // This will return both iv and ciphertext
    public byte[] encrypt() {
      return AESDemo.encrypt(secretKey, secretMessage);
    }
  }


  private static class Receiver {
    private byte[] secretKey;

    public Receiver(byte[] secretKey) {
      this.secretKey = secretKey;
    }

    // Padding Oracle (Notice the return type)
    public boolean isDecryptionSuccessful(byte[] ciphertext) {
      return AESDemo.decrypt(secretKey, ciphertext) != null;
    }
  }


  public static class Adversary {

    // This is where you are going to develop the attack
    // Assume you cannot access the key.
    // You shall not add any methods to the Receiver class.
    // You only have access to the receiver's "isDecryptionSuccessful" only.
    public String extractSecretMessage(Receiver receiver, byte[] ciphertext) {
      byte[] iv = AESDemo.extractIV(ciphertext);
      byte[] ciphertextBlocks = AESDemo.extractCiphertextBlocks(ciphertext);
      byte secretMessage[] = new byte[ciphertextBlocks.length];
      byte messageLength;
      for (messageLength = 0; messageLength < ciphertextBlocks.length; messageLength++) {
        iv[messageLength] = (byte) (iv[messageLength] ^ 0b1);
        boolean result = receiver.isDecryptionSuccessful(AESDemo.prepareCiphertext(iv, ciphertextBlocks));
        iv[messageLength] = (byte) (iv[messageLength] ^ 0b1);
        if (!result) {
          break;
        }
      }
      byte paddingLength;
      paddingLength = (byte)(ciphertextBlocks.length - messageLength);
      byte[] workingIv = new byte[iv.length];
            byte[] oldWorkingIv = new byte[iv.length];
      workingIv = iv.clone();
      for (int i = messageLength; i < ciphertextBlocks.length; i++) {
        secretMessage[i] = paddingLength;
      }
      byte found = (byte) paddingLength;
      while (found != (ciphertextBlocks.length)) {
                oldWorkingIv=workingIv.clone();
        for (int backwardIterator = iv.length - 1; backwardIterator > (messageLength - 1 - found + paddingLength); backwardIterator--) {
          workingIv[backwardIterator] = (byte) (oldWorkingIv[backwardIterator] ^ found ^ (found + 1));
        }
        for (int i = 0; i < 256; i++) {
          workingIv[iv.length - found - 1] = (byte) i;

          boolean result = receiver.isDecryptionSuccessful(AESDemo.prepareCiphertext(workingIv, ciphertextBlocks));
          if (result) {
            secretMessage[iv.length - found - 1] = (byte) (i ^ iv[iv.length - found - 1] ^ (found + 1));
            break;
          }
        }
        found = (byte)(found + 1);
      }

      return new String(secretMessage, 0, messageLength);
    }
  }

  public static void main(String[] args) {

    byte[] secretKey = AESDemo.keyGen();
    Sender sender = new Sender(secretKey);
    Receiver receiver = new Receiver(secretKey);

    // The adversary does not have the key
    Adversary adversary = new Adversary();

    // Now, let's get some valid encryption from the sender
    byte[] ciphertext = sender.encrypt();

    // The adversary  got the encrypted message from the network.
    // The adversary's goal is to extract the message without knowing the key.
    String message = adversary.extractSecretMessage(receiver, ciphertext);

    System.out.println("Extracted message = " + message);
  }
}
