using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using UnityEngine;
using Debug = UnityEngine.Debug;


namespace Newleaf.Http.Oauth
{
    public interface ILogger
    {
        void Log(string _message);
    }
    
    public class OauthLoginServer
    {
        
        public event EventHandler<string> HandleAccessToken; 
        // client configuration
        public string clientID = "63d32a9d-8960-4d2e-9826-6b0ee2b477c9";
        public string authorizationEndpoint = "https://newleafms.b2clogin.com/newleafms.onmicrosoft.com/B2C_1_signupandin/oauth2/v2.0/authorize";
        public string tokenEndpoint = "https://newleafms.b2clogin.com/newleafms.onmicrosoft.com/B2C_1_signupandin/oauth2/v2.0/token";
        private ILogger Logger;

        public OauthLoginServer (ILogger _logger)
        {
            Logger = _logger;
        }

        protected virtual void OnHandleAccessToken (string _e)
        {
            EventHandler<string> _handler = HandleAccessToken;
            _handler?.Invoke(this, _e);
        }

        public async void pkceLogin ()
        {
            // Generates state and PKCE values.
            string _state = randomDataBase64url(32);
            string _codeVerifier = randomDataBase64url(32);
            string _codeChallenge = base64urlencodeNoPadding(sha256(_codeVerifier));
            const string code_challenge_method = "S256";

            // Creates an HttpListener to listen for requests on that redirect URI.
            var http = new HttpServer();
            http.Start();

            // Creates the OAuth 2.0 authorization request.
            string authorizationRequest = string.Format("{0}?response_type=code&scope=offline_access {6}&redirect_uri={1}&client_id={2}&state={3}&code_challenge={4}&code_challenge_method={5}",
                authorizationEndpoint,
                Uri.EscapeDataString(http.Url),
                clientID,
                _state,
                _codeChallenge,
                code_challenge_method,
                clientID);

            // Opens request in the browser.
            Process.Start(new ProcessStartInfo {FileName = authorizationRequest, UseShellExecute = true});
            // Waits for the OAuth authorization response.
            var context = await http.listener.GetContextAsync();

            // Sends an HTTP response to the browser.
            var response = context.Response;
            string responseString = "<html><head></head><body>Please return to the app.</body></html>";
            var buffer = Encoding.UTF8.GetBytes(responseString);
            response.ContentLength64 = buffer.Length;
            var responseOutput = response.OutputStream;
            await responseOutput.WriteAsync(buffer, 0, buffer.Length).ContinueWith((task) =>
            {
                responseOutput.Close();
                http.Stop();
                task.Dispose();
            });

            // extracts the code
            var code = context.Request.QueryString.Get("code");
            var incoming_state = context.Request.QueryString.Get("state");
            
            if (context.Request.QueryString.Get("error") != null || context.Request.QueryString.Get("code") == null || context.Request.QueryString.Get("state") == null || incoming_state != _state)
                return;

            // Starts the code exchange at the Token Endpoint.
            performCodeExchange(code, _codeVerifier, http.Url);
        }

        async void performCodeExchange (string code, string code_verifier, string redirectURI)
        {
            // builds the  request
            string tokenRequestBody = string.Format("code={0}&redirect_uri={1}&client_id={2}&code_verifier={3}&scope=&grant_type=authorization_code",
                code,
                Uri.EscapeDataString(redirectURI),
                clientID,
                code_verifier
            );

            // sends the request
            HttpWebRequest tokenRequest = (HttpWebRequest) WebRequest.Create(tokenEndpoint);
            tokenRequest.Method = "POST";
            tokenRequest.ContentType = "application/x-www-form-urlencoded";
            byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenRequestBody);
            tokenRequest.ContentLength = _byteVersion.Length;
            Stream stream = tokenRequest.GetRequestStream();
            await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
            stream.Close();

            try
            {
                // gets the response
                WebResponse tokenResponse = await tokenRequest.GetResponseAsync();
                using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
                {
                    // reads response body
                    string responseText = await reader.ReadToEndAsync();
                    // converts to dictionary
                    Dictionary<string, string> tokenEndpointDecoded = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);

                    string access_token = tokenEndpointDecoded["access_token"];
                    OnHandleAccessToken(access_token);
                }
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    if (response != null)
                    {
                        Logger.Log("HTTP: " + response.StatusCode);
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            // reads response body
                            string responseText = await reader.ReadToEndAsync();
                            Logger.Log(responseText);
                        }
                    }
                }
            }
        }

        public static string randomDataBase64url (uint length)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return base64urlencodeNoPadding(bytes);
        }

        public static byte[] sha256 (string inputStirng)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(inputStirng);
            SHA256Managed sha256 = new SHA256Managed();
            return sha256.ComputeHash(bytes);
        }

        public static string base64urlencodeNoPadding (byte[] buffer)
        {
            string base64 = Convert.ToBase64String(buffer);

            // Converts base64 to base64url.
            base64 = base64.Replace("+", "-");
            base64 = base64.Replace("/", "_");
            // Strips padding.
            base64 = base64.Replace("=", "");

            return base64;
        }
    }
}