import * as crypto from "node:crypto";

export class PacketEncryptor {
   private secretKeyBytes: Uint8Array;
   private sendCounter = 0n;
   private receiveCounter = 0n;
   private cipher: crypto.CipherGCM | null = null;
   private decipher: crypto.DecipherGCM | null = null;

   constructor(secretKeyBytes: Buffer, iv: Buffer) {
      this.secretKeyBytes = new Uint8Array(secretKeyBytes);
      this.initializeCipher(iv);
      this.initializeDecipher(iv);
   }

   destroy(): void {
      this.cipher = null;
      this.decipher = null;
   }

   private initializeCipher(iv: Buffer): void {
      this.cipher = crypto.createCipheriv(
         "aes-256-gcm",
         new Uint8Array(this.secretKeyBytes),
         new Uint8Array(iv.subarray(0, 12)),
      ) as crypto.CipherGCM;
   }

   private initializeDecipher(iv: Buffer): void {
      this.decipher = crypto.createDecipheriv(
         "aes-256-gcm",
         new Uint8Array(this.secretKeyBytes),
         new Uint8Array(iv.subarray(0, 12)),
      ) as crypto.DecipherGCM;
   }

   private computeCheckSum(packetPlaintext: Buffer, counter: bigint): Buffer {
      const digest = crypto.createHash("sha256");
      const counterBuffer = Buffer.alloc(8);
      counterBuffer.writeBigInt64LE(counter, 0);
      digest.update(new Uint8Array(counterBuffer));
      digest.update(new Uint8Array(packetPlaintext));
      digest.update(this.secretKeyBytes);
      const hash = digest.digest();
      return Buffer.from(new Uint8Array(hash.subarray(0, 8)));
   }

   encryptPacket(payload: Buffer): Buffer {
      if (!this.cipher) {
         // Cipher destroyed - return unencrypted
         return Buffer.concat([Buffer.from([0xfe]), payload]);
      }
      try {
         const checksum = this.computeCheckSum(payload, this.sendCounter);
         const toEncrypt = Buffer.concat([payload, checksum]);
         const encrypted = this.cipher.update(toEncrypt);
         this.sendCounter++;
         return Buffer.concat([Buffer.from([0xfe]), encrypted]);
      } catch {
         // Cipher in invalid state - return unencrypted
         return Buffer.concat([Buffer.from([0xfe]), payload]);
      }
   }

   decryptPacket(encryptedPayload: Buffer): Buffer {
      if (!this.decipher) {
         // Decipher destroyed - return as-is
         return encryptedPayload;
      }
      try {
         const decrypted = this.decipher.update(encryptedPayload);
         const packet = decrypted.subarray(0, decrypted.length - 8);
         const receivedChecksum = decrypted.subarray(decrypted.length - 8);
         const computedChecksum = this.computeCheckSum(packet, this.receiveCounter);
         this.receiveCounter++;
         if (!receivedChecksum.equals(computedChecksum)) {
            throw new Error("Checksum mismatch");
         }
         return packet;
      } catch (err) {
         // Re-throw checksum errors, ignore cipher state errors
         if (err instanceof Error && err.message === "Checksum mismatch") {
            throw err;
         }
         return encryptedPayload;
      }
   }
}
