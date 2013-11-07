import std.stdio, std.conv, std.getopt, std.file, std.string;
import aes.simple;

int main(string[] args)
{
    string inputFile;
    string outputFile;
    string keyFile;
    ubyte[] key;
    BlockMode mode = BlockMode.ECB;
    bool encrypt;
    File input = stdin;
    File output = stdout;
    
    if (args.length > 1) {
        if (args[1] == "encrypt"){
            encrypt = true;
        } else if (args[1] == "decrypt") {
            encrypt = false;
        } else {
            printHelp(args[0]);
            return 1;
        }
    } else {
        printHelp(args[0]);
        return 1;
    }
    
    void parseMode(string k, string v)
    {
        switch (toUpper(v)) {
            case "CBC":
                mode = BlockMode.CBC;
                break;
            case "ECB":
                mode = BlockMode.ECB;
                break;
            default:
                throw new Exception(v ~ " is not a valid mode");
        }
    }
    
    try {
        
        getopt(args,
            "input", &inputFile,
            "output", &outputFile,
            "key-file", &keyFile,
            "mode", &parseMode
        );
        
    } catch (Exception e) {
        stderr.writeln("error: ", e);
        return 1;
    }
    
    if (!keyFile) {
        stderr.writeln("error: must specify key file");
        return 1;
    }
    
    try {
        auto keySize = getSize(keyFile);
        if (keySize != 16 && keySize != 24 && keySize != 32){
            stderr.writeln("error: invalid key size");
            return 1;
        }
        
        key = cast(ubyte[]) read(keyFile);
        
        if (inputFile)
            input = File(inputFile, "rb");
        if (outputFile)
            output = File(outputFile, "wb");
        
        if (encrypt)
            aesEncrypt(input, output, key, mode);
        else
            aesDecrypt(input, output, key, mode);
        
    } catch (Exception e) {
        stderr.writeln("I/O error: ", e);
        return 1;
    }
    
    return 0;
}

void printHelp(string name)
{
    stderr.writeln("usage: ", name, " <encrypt|decrypt> --key-file <file> [--input <file>] [--output <file>]");
    stderr.writeln("The entire key file will be used as the key. It must be exactly 16, 24, or 32 bytes.");
    stderr.writeln("If an input file or output file is not supplied, then standard in/out is used.");
}
