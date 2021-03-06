/**
 * Contains functions which will encrypt entire files or byte arrays and
 * automatically handle block cipher modes and padding. Specifically,
 * the functions use a padding scheme in which the last block is filled
 * with bytes 0x80 0x00 0x00 0x00 ... 0x00. If the input is already a
 * multiple of the block size (which is 128 bits), then an extra block
 * of padding is added with the aforementioned bytes.
 */
module aes.util;

import std.stdio;
import aes.encryptor, aes.decryptor, aes.common;

/// Enumeration of available block cipher modes of operation.
enum BlockMode { 
    CBC, /// cipher-block chaining
    ECB  /// electronic codebook
};

/// Encrypts a buffer of plaintext and returns a new buffer containing the ciphertext.
ubyte[] encrypt(const ubyte[] plain, const ubyte[] key, BlockMode mode = BlockMode.ECB)
in {
    auto keySize = key.length * 8;
    assert(keySize == 128 || keySize == 192 || keySize == 256);
}
body {
    ubyte[] cipher = new ubyte[(plain.length / 16 + 1) * 16];
    cipher[] = plain[];
    cipher[plain.length] = 0x80;
    cipher[plain.length .. $] = 0x00;
    
    auto encryptor = createEncryptor(key);
    
    if (mode == BlockMode.CBC) {
        encryptor.processBlock(cipher[0..16]);
        
        for (int i = 16; i < cipher.length; i += 16) {
            cipher[i .. i + 16] ^= cipher[i - 16 .. i];
            encryptor.processBlock(cipher[i .. i + 16]);
        }
    } else {
        encryptor.processChunk(cipher);
    }
    
    return cipher;
}

/// Decrypts a buffer of ciphertext and returns a new buffer containing the plaintext.
ubyte[] decrypt(const ubyte[] cipher, const ubyte[] key, BlockMode mode = BlockMode.ECB)
in {
    auto keySize = key.length * 8;
    assert(keySize == 128 || keySize == 192 || keySize == 256);
    assert(cipher.length % 16 == 0);
    assert(cipher.length != 0);
}
body {
    ubyte[] plain = cipher.dup;
    auto decryptor = createDecryptor(key);
    
    if (mode == BlockMode.CBC) {
        decryptor.processBlock(plain[0..16]);
        
        for (size_t i = 16; i < plain.length; i += 16) {
            decryptor.processBlock(plain[i .. i + 16]);
            plain[i .. i + 16] ^= cipher[i - 16 .. i];
        }
    } else {
        decryptor.processChunk(plain);
    }
    
    size_t padStart = plain.length - 1;
    while (plain[padStart] == 0x00 && padStart >= 0)
        padStart--;
    
    if (plain[padStart] != 0x80)
        throw new Exception("malformed padding");
    
    return plain[0 .. padStart];
}

/// Encrypts an entire input stream and writes it to an output stream.
void encrypt(File input, File output, const ubyte[] key, BlockMode mode = BlockMode.ECB)
in {
    auto keySize = key.length * 8;
    assert(keySize == 128 || keySize == 192 || keySize == 256);
    assert(input.isOpen());
    assert(output.isOpen());
}
body {
    ubyte[] block = new ubyte[16];
    ubyte[] prevBlock = new ubyte[16];
    auto encryptor = createEncryptor(key);
    size_t amtRead = block.length;
    
    while (amtRead == block.length) {
        
        amtRead = input.rawRead(block).length;
        
        if (amtRead < block.length) {
            // we have reached eof, so we need to pad
            block[amtRead] = 0x80;
            block[amtRead + 1 .. $] = 0x00;
        }
        
        if (mode == BlockMode.CBC) 
            block[] ^= prevBlock[];
        
        encryptor.processBlock(block);
        output.rawWrite(block);
        
        if (mode == BlockMode.CBC) 
            prevBlock[] = block[];
    }
}

/// Decrypts an entire input stream and writes it to an output stream.
void decrypt(File input, File output, const ubyte[] key, BlockMode mode = BlockMode.ECB)
in {
    auto keySize = key.length * 8;
    assert(keySize == 128 || keySize == 192 || keySize == 256);
    assert(input.isOpen());
    assert(output.isOpen());
}
body {
    ubyte[] block = new ubyte[16];
    ubyte[] prevBlock = new ubyte[16];
    ubyte[] nextBlock = new ubyte[16];
    auto decryptor = createDecryptor(key);
    
    auto amtRead = input.rawRead(nextBlock).length;
    if (amtRead < nextBlock.length)
        throw new Exception("stream length not a multiple of block size");
    
    do {
        
        block[] = nextBlock[];
        decryptor.processBlock(block);
        
        if (mode == BlockMode.CBC) {
            block[] ^= prevBlock[];
            // at this point, prevBlock contains the ciphertext
            // for the previous block, block contains the plaintext
            // for the current block, and nextBlock contains the
            // ciphertext for the current block.
            prevBlock[] = nextBlock[];
        }
        
        amtRead = input.rawRead(nextBlock).length;
        if (amtRead == 0) {
            // we've reached EOF, so the current block is the last 
            // block in the stream, so we need to remove the padding
            
            size_t padStart = block.length - 1;
            while (block[padStart] == 0x00 && padStart >= 0)
                padStart--;
            
            if (block[padStart] != 0x80)
                throw new Exception("malformed padding");
            
            block = block[0 .. padStart];
            
        } else if (amtRead < nextBlock.length)
            throw new Exception("stream length not a multiple of block size");
        
        output.rawWrite(block);
        
    } while (amtRead == nextBlock.length);
}
