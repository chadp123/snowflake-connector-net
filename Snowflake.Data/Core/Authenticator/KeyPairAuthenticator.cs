using System;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Snowflake.Data.Client;
using Snowflake.Data.Core;
using Snowflake.Data.Log;

namespace Snowflake.Data.Core.Authenticator
{
    /// <summary>
    /// KeyPairAuthenticator is used for Key pair based authentication.
    /// See <see cref="https://docs.snowflake.com/en/user-guide/key-pair-auth.html"/> for more information.
    /// </summary>
    class KeyPairAuthenticator : BaseAuthenticator, IAuthenticator
    {
        // The authenticator setting value to use to authenticate using key pair authentication.
        public const string AUTH_NAME = "snowflake_jwt";

        // Retry configuration constants
        private const int MaxAuthRetries = 3;
        private const int JwtLifetimeSeconds = 60;
        private const int InitialBackoffMs = 1000;
        private const int MaxBackoffMs = 8000;

        // Retryable Snowflake error codes for JWT authentication
        private static readonly int[] s_retryableSnowflakeCodes = {
            394303,  // JWT_TOKEN_INVALID_EXPIRATION_TIME
            394304,  // JWT_TOKEN_INVALID_PUBLIC_KEY_FINGERPRINT_MISMATCH
            390144,  // JWT_TOKEN_INVALID
        };

        // Retryable HTTP status codes
        private static readonly int[] s_retryableHttpCodes = { 500, 502, 503, 504, 408, 429 };

        // The logger.
        private static readonly SFLogger logger =
            SFLoggerFactory.GetLogger<KeyPairAuthenticator>();

        // The RSA provider to use to sign the tokens
        private RSACryptoServiceProvider rsaProvider;

        // The jwt token to send in the login request.
        private string jwtToken;

        /// <summary>
        /// Constructor for the Key-Pair authenticator.
        /// </summary>
        /// <param name="session">Session which created this authenticator</param>
        internal KeyPairAuthenticator(SFSession session) : base(session, AUTH_NAME)
        {
            this.session = session;
            this.rsaProvider = new RSACryptoServiceProvider();
        }

        public static bool IsKeyPairAuthenticator(string authenticator) =>
            AUTH_NAME.Equals(authenticator, StringComparison.InvariantCultureIgnoreCase);

        /// <see cref="IAuthenticator.AuthenticateAsync"/>
        async public Task AuthenticateAsync(CancellationToken cancellationToken)
        {
            Exception lastException = null;
            int backoffMs = InitialBackoffMs;

            for (int attempt = 1; attempt <= MaxAuthRetries; attempt++)
            {
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    // Generate fresh JWT token on every attempt (like Python connector)
                    jwtToken = GenerateJwtToken();

                    logger.Info($"JWT Authentication async attempt {attempt}/{MaxAuthRetries}");
                    await base.LoginAsync(cancellationToken).ConfigureAwait(false);

                    logger.Info("JWT Authentication successful");
                    return;
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (SnowflakeDbException ex) when (ShouldRetry(ex, attempt))
                {
                    lastException = ex;
                    logger.Warn($"JWT auth async attempt {attempt} failed with error {ex.ErrorCode}: {ex.Message}. Retrying with fresh token.");

                    if (attempt < MaxAuthRetries)
                    {
                        int sleepTime = CalculateBackoff(backoffMs);
                        logger.Debug($"Waiting {sleepTime}ms before retry...");
                        await Task.Delay(sleepTime, cancellationToken).ConfigureAwait(false);
                        backoffMs = Math.Min(backoffMs * 2, MaxBackoffMs);
                    }
                }
                catch (Exception ex)
                {
                    logger.Error($"JWT Authentication async failed with non-retryable error: {ex.Message}", ex);
                    throw;
                }
            }

            throw new SnowflakeDbException(
                SFError.INTERNAL_ERROR,
                $"JWT Authentication failed after {MaxAuthRetries} attempts. Last error: {lastException?.Message}");
        }

        /// <see cref="IAuthenticator.Authenticate"/>
        public void Authenticate()
        {
            Exception lastException = null;
            int backoffMs = InitialBackoffMs;

            for (int attempt = 1; attempt <= MaxAuthRetries; attempt++)
            {
                try
                {
                    // Generate fresh JWT token on every attempt (like Python connector)
                    jwtToken = GenerateJwtToken();

                    logger.Info($"JWT Authentication attempt {attempt}/{MaxAuthRetries}");
                    base.Login();

                    logger.Info("JWT Authentication successful");
                    return;
                }
                catch (SnowflakeDbException ex) when (ShouldRetry(ex, attempt))
                {
                    lastException = ex;
                    logger.Warn($"JWT auth attempt {attempt} failed with error {ex.ErrorCode}: {ex.Message}. Retrying with fresh token.");

                    if (attempt < MaxAuthRetries)
                    {
                        int sleepTime = CalculateBackoff(backoffMs);
                        logger.Debug($"Waiting {sleepTime}ms before retry...");
                        Thread.Sleep(sleepTime);
                        backoffMs = Math.Min(backoffMs * 2, MaxBackoffMs);
                    }
                }
                catch (Exception ex)
                {
                    logger.Error($"JWT Authentication failed with non-retryable error: {ex.Message}", ex);
                    throw;
                }
            }

            throw new SnowflakeDbException(
                SFError.INTERNAL_ERROR,
                $"JWT Authentication failed after {MaxAuthRetries} attempts. Last error: {lastException?.Message}");
        }

        /// <see cref="BaseAuthenticator.SetSpecializedAuthenticatorData(ref LoginRequestData)"/>
        protected override void SetSpecializedAuthenticatorData(ref LoginRequestData data)
        {
            data.Token = jwtToken;
            SetSecondaryAuthenticationData(ref data);
        }

        /// <summary>
        /// Determines if authentication should be retried based on the exception.
        /// </summary>
        private bool ShouldRetry(SnowflakeDbException ex, int attempt)
        {
            if (attempt >= MaxAuthRetries)
                return false;

            return s_retryableHttpCodes.Contains(ex.ErrorCode) ||
                   s_retryableSnowflakeCodes.Contains(ex.ErrorCode);
        }

        /// <summary>
        /// Calculates backoff time with jitter.
        /// </summary>
        private int CalculateBackoff(int baseBackoffMs)
        {
            int jitter = new Random().Next(-500, 500);
            return Math.Max(100, baseBackoffMs + jitter);
        }

        /// <summary>
        /// Generates a JwtToken to use for login.
        /// </summary>
        private string GenerateJwtToken()
        {
            logger.Debug("Generating JWT token for key-pair authentication");

            bool hasPkPath =
                session.properties.TryGetValue(SFSessionProperty.PRIVATE_KEY_FILE, out var pkPath);
            bool hasPkContent =
                session.properties.TryGetValue(SFSessionProperty.PRIVATE_KEY, out var pkContent);
            session.properties.TryGetValue(SFSessionProperty.PRIVATE_KEY_PWD, out var pkPwd);

            // Extract the public key from the private key to generate the fingerprints
            RSAParameters rsaParams;
            String publicKeyFingerPrint = null;
            AsymmetricCipherKeyPair keypair = null;
            using (TextReader tr =
                hasPkPath ? (TextReader)new StreamReader(pkPath) : new StringReader(pkContent))
            {
                try
                {
                    using (PemReader pr = CreatePemReader(tr, pkPwd))
                    {
                        object key = pr.ReadObject();
                        // Infer what the pem reader is sending back based on the object properties
                        if (key.GetType().GetProperty("Private") != null)
                        {
                            // PKCS1 key
                            keypair = (AsymmetricCipherKeyPair)key;
                            rsaParams = DotNetUtilities.ToRSAParameters(
                                keypair.Private as RsaPrivateCrtKeyParameters);
                        }
                        else
                        {
                            // PKCS8 key
                            RsaPrivateCrtKeyParameters pk = (RsaPrivateCrtKeyParameters)key;
                            rsaParams = DotNetUtilities.ToRSAParameters(pk);
                            keypair = DotNetUtilities.GetRsaKeyPair(rsaParams);
                        }

                        if (keypair == null)
                        {
                            throw new Exception("Unknown error.");
                        }
                    }
                }
                catch (Exception e)
                {
                    throw new SnowflakeDbException(
                        e,
                        SFError.JWT_ERROR_READING_PK,
                        hasPkPath ? pkPath : "with value passed in connection string",
                        (pkContent == null) ? e.ToString() : "incorrect private key value or " +
                        "private key format: use \"\\n\" for newlines and double the equals sign.");
                }
            }

            // Generate the public key fingerprint
            var publicKey = keypair.Public;
            byte[] publicKeyEncoded =
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).GetDerEncoded();
            using (SHA256 SHA256Encoder = SHA256.Create())
            {
                byte[] sha256Hash = SHA256Encoder.ComputeHash(publicKeyEncoded);
                publicKeyFingerPrint = "SHA256:" + Convert.ToBase64String(sha256Hash);
            }

            // Generating the token
            var now = DateTime.UtcNow;
            System.DateTime dtDateTime =
                new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
            long secondsSinceEpoch = (long)((now - dtDateTime).TotalSeconds);

            /*
             * Payload content
             *      iss : $accountName.$userName.$publicKeyFingerprint
             *      sub : $accountName.$userName
             *      iat : $now
             *      exp : $now + LIFETIME
             *
             * Note : Lifetime = 120sec for Python impl, 60sec for Jdbc and Odbc
            */
            String accountUser =
                session.properties[SFSessionProperty.ACCOUNT].ToUpper() +
                "." +
                session.properties[SFSessionProperty.USER].ToUpper();
            String issuer = accountUser + "." + publicKeyFingerPrint;
            var claims = new[] {
                        new Claim(
                            JwtRegisteredClaimNames.Iat,
                            secondsSinceEpoch.ToString(),
                            System.Security.Claims.ClaimValueTypes.Integer64),
                        new Claim(JwtRegisteredClaimNames.Sub, accountUser),
                    };

            rsaProvider.ImportParameters(rsaParams);
            var token = new JwtSecurityToken(
                // Issuer
                issuer,
                // Audience
                null,
                // Subject
                claims,
                //NotBefore
                null,
                // Expires
                now.AddSeconds(JwtLifetimeSeconds),
                //SigningCredentials
                new SigningCredentials(
                    new RsaSecurityKey(rsaProvider), SecurityAlgorithms.RsaSha256)
            );

            // Serialize the jwt token
            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(token);
        }

        private PemReader CreatePemReader(TextReader textReader, string privateKeyPassword)
        {
            if (null != privateKeyPassword)
            {
                IPasswordFinder ipwdf = new PasswordFinder(privateKeyPassword);
                return new PemReader(textReader, ipwdf);
            }
            else
            {
                return new PemReader(textReader);
            }
        }

        /// <summary>
        /// Helper class to handle the password for the certificate if there is one.
        /// </summary>
        private class PasswordFinder : IPasswordFinder
        {
            private string password;

            public PasswordFinder(string password)
            {
                this.password = password;
            }

            public char[] GetPassword()
            {
                if ((null == password) || (0 == password.Length))
                {
                    return null;
                }
                else
                {
                    return password.ToCharArray();
                }
            }
        }
    }
}
