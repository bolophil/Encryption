using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;

/// <summary>
/// Provides a base class for implementing an Echo client.
/// </summary>
internal sealed class EncryptedEchoClient : EchoClientBase
{

    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoClient> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoClient>()!;

    /// <inheritdoc />
    public EncryptedEchoClient(ushort port, string address) : base(port, address) { }
    /// <inheritdoc />
    private RSA serverRsa = RSA.Create(2048);

    public override void ProcessServerHello(string message)
    {

        // todo: Step 1: Get the server's public key. Decode using Base64.
        // Throw a CryptographicException if the received key is invalid.
        try
        {
            byte[] decodedKey = Convert.FromBase64String(message);
            //RSA key is 2048 in size from above so if the key is invlad the ImportRSAPublickey will fail
            serverRsa.ImportRSAPublicKey(decodedKey, out _);
            Logger.LogInformation("Puclic key loaded from server hello");
        }
        catch
        {
            throw new CryptographicException("Invalid server public key");
        }
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input)
    {
        byte[] data = Settings.Encoding.GetBytes(input);

        // todo: Step 1: Encrypt the input using hybrid encryption.
        // Encrypt using AES with CBC mode and PKCS7 padding.
        // Use a different key each time.
        Aes aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        // This should give different key each time
        aes.GenerateKey();
        aes.GenerateIV();
        // todo: Step 2: Generate an HMAC of the message.
        // Use the SHA256 variant of HMAC.
        // Use a different key each time.
        // This should give different key each time
        HMACSHA256 hmac = new HMACSHA256();
        byte[] hashHmac = hmac.ComputeHash(data);
        // todo: Step 3: Encrypt the message encryption and HMAC keys using RSA.
        // Encrypt using the OAEP padding scheme with SHA256.
        ICryptoTransform encryptor = aes.CreateEncryptor();
        byte[] encryptedMessage = encryptor.TransformFinalBlock(data, 0, data.Length);

        byte[] aesKeyWrap = serverRsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
        byte[] hmacKeyWrap = serverRsa.Encrypt(hmac.Key, RSAEncryptionPadding.OaepSHA256);

        // todo: Step 4: Put the data in an EncryptedMessage object and serialize to JSON.
        // Return that JSON.
        // var message = new EncryptedMessage(...);
        // return JsonSerializer.Serialize(message);
        var message = new EncryptedMessage(aesKeyWrap, aes.IV, encryptedMessage, hmacKeyWrap, hashHmac);
        return JsonSerializer.Serialize(message);

    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input)
    {
        // todo: Step 1: Deserialize the message.
        var signedMessage = JsonSerializer.Deserialize<SignedMessage>(input);

        // todo: Step 2: Check the messages signature.
        // Use PSS padding with SHA256.
        // Throw an InvalidSignatureException if the signature is bad.

        if (!serverRsa.VerifyData(signedMessage.Message, signedMessage.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
        {
            throw new InvalidSignatureException("Invalid signature.");
        }

        // todo: Step 3: Return the message from the server.
        return Settings.Encoding.GetString(signedMessage.Message);

    }
}