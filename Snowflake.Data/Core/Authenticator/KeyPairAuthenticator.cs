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
    /// 
    /// ROOT CAUSE OF JWT EXPIRATION ISSUES:
    /// =====================================
    /// JWT tokens have a hardcoded 60-second lifetime. When HTTP errors occur (e.g., 503 Service Unavailable),
    /// the HTTP-level RetryHandler (in HttpUtil.cs) retries the request using the SAME JWT token.
    /// If the total retry duration exceeds 60 seconds, the JWT expires, causing Snowflake to return
    /// error 394303 (JWT_TOKEN_INVALID_EXPIRATION_TIME).
    /// 
    /// SOLUTION:
    /// This implementation adds authenticator-level retry that regenerates the JWT token on each attempt,
    /// matching the Python connector's behavior (see auth/keypair.py handle_timeout method).
    /// 
    /// INTERACTION WITH HTTP RETRY HANDLER:
    /// - HTTP RetryHandler (HttpUtil.cs) handles transport-level retries for 503/5xx errors
    /// - HTTP RetryHandler uses the SAME JWT token for all retries (this is the bug)
    /// - This authenticator catches Snowflake error 394303 (JWT_TOKEN_INVALID_EXPIRATION_TIME) AFTER HTTP retries exhaust
    /// - On catching this error, we regenerate the JWT and retry the entire authentication
    /// - Other JWT errors (394304, 390144) are not retried as they indicate configuration/implementation issues
    /// - The connection string parameters MAXHTTPRETRIES and RETRY_TIMEOUT still control HTTP-level retries
    /// 
    /// RETRY CONFIGURATION:
    /// - MaxAuthRetries: Number of times to regenerate JWT and retry (default: 3)
    /// - HTTP retries: Controlled by MAXHTTPRETRIES connection string parameter (default: 7)
    /// - Total worst-case attempts: MaxAuthRetries * MAXHTTPRETRIES
    /// </summary>
    class KeyPairAuthenticator : BaseAuthenticator, IAuthenticator
    {
        // The authenticator setting value to use to authenticate using key pair authentication.
        public const string AUTH_NAME = "snowflake_jwt";

        /// <summary>
        /// Maximum number of authentication retries with fresh JWT tokens.
        /// This is separate from HTTP-level retries (MAXHTTPRETRIES).
        /// </summary>
        private const int MaxAuthRetries = 3;
        
        /// <summary>
        /// JWT token lifetime in seconds. Matches JDBC/ODBC drivers.
        /// Python uses 60s by default but allows override via JWT_LIFETIME_IN_SECONDS env var.
        /// </summary>
        private const int JwtLifetimeSeconds = 60;
        
        /// <summary>
        /// Initial backoff between authenticator-level retries in milliseconds.
        /// </summary>
        private const int InitialBackoffMs = 1000;
        
        /// <summary>
        /// Maximum backoff between authenticator-level retries in milliseconds.
        /// </summary>
        private const int MaxBackoffMs = 8000;

        /// <summary>
        /// Snowflake error code that indicates JWT token expiration and should trigger retry with fresh token.
        /// Only 394303 (JWT_TOKEN_INVALID_EXPIRATION_TIME) is retryable - it occurs when the JWT expires
        /// during HTTP-level retries.
        /// 
        /// Other JWT errors (394304 PUBLIC_KEY_FINGERPRINT_MISMATCH, 390144 JWT_TOKEN_INVALID) indicate
        /// configuration or implementation errors that won't be fixed by regenerating the JWT.
        /// </summary>
        private static readonly int[] s_retryableSnowflakeCodes = {
            394303,  // JWT_TOKEN_INVALID_EXPIRATION_TIME - JWT expired during HTTP retries
        };

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

                    // Generate fresh JWT token on every attempt (matches Python connector pattern)
                    // This ensures JWT never expires during HTTP-level retries
                    jwtToken = GenerateJwtToken();

                    logger.Info($"JWT Authentication async attempt {attempt}/{MaxAuthRetries}");
                    
                    // Login() will use HTTP RetryHandler for transport-level retries (503, etc.)
                    // If JWT expires during those retries, we'll catch the error below
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
                    logger.Warn($"JWT auth async attempt {attempt} failed with Snowflake error {ex.ErrorCode}: {ex.Message}. " +
                               $"Regenerating JWT token for retry.");

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
                    // Generate fresh JWT token on every attempt (matches Python connector pattern)
                    // This ensures JWT never expires during HTTP-level retries
                    jwtToken = GenerateJwtToken();

                    logger.Info($"JWT Authentication attempt {attempt}/{MaxAuthRetries}");
                    
                    // Login() will use HTTP RetryHandler for transport-level retries (503, etc.)
                    // If JWT expires during those retries, we'll catch the error below
                    base.Login();

                    logger.Info("JWT Authentication successful");
                    return;
                }
                catch (SnowflakeDbException ex) when (ShouldRetry(ex, attempt))
                {
                    lastException = ex;
                    logger.Warn($"JWT auth attempt {attempt} failed with Snowflake error {ex.ErrorCode}: {ex.Message}. " +
                               $"Regenerating JWT token for retry.");

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
        /// Determines if authentication should be retried based on the Snowflake error code.
        /// Only retries on JWT-specific errors - HTTP transport errors are handled by RetryHandler.
        /// </summary>
        private bool ShouldRetry(SnowflakeDbException ex, int attempt)
        {
            if (attempt >= MaxAuthRetries)
                return false;

            // Only retry on Snowflake JWT errors, not HTTP errors
            // HTTP errors (503, etc.) are handled by the HTTP RetryHandler
            return s_retryableSnowflakeCodes.Contains(ex.ErrorCode);
        }

        /// <summary>
        /// Calculates backoff time with jitter to prevent thundering herd.
        /// </summary>
        private int CalculateBackoff(int baseBackoffMs)
        {
            int jitter = new Random().Next(-500, 500);
            return Math.Max(100, baseBackoffMs + jitter);
        }

        /// <summary>
        /// Generates a fresh JWT token for authentication.
        /// Called at the start of each authentication attempt to ensure token validity.
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
             *      exp : $now + LIFETIME (60 seconds)
             *
             * Note: Lifetime = 120sec for Python impl, 60sec for Jdbc/Odbc/.NET
             * The short lifetime is why we must regenerate on retries.
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
                // Expires - 60 second lifetime
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
            // The password.
            private string password;

            /// <summary>
            /// Constructor.
            /// </summary>
            /// <param name="password">The password.</param>
            public PasswordFinder(string password)
            {
                this.password = password;
            }

            /// <summary>
            /// Returns the password or null if the password is empty or null.
            /// </summary>
            /// <returns>The password or null.</returns>
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
