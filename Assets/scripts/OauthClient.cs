using System.Collections.Generic;
using System;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Newtonsoft.Json;
using Debug = UnityEngine.Debug;

namespace Newleaf.Oauth
{
    public class OauthClient
    {
        // client configuration
    public string clientID = "63d32a9d-8960-4d2e-9826-6b0ee2b477c9";
    public string clientSecret = "UUb8Q~vRey6AUhQRLnNDS-b6E3nbMXQDdA3ETbH5";
    public string authorizationEndpoint = "https://newleafms.b2clogin.com/newleafms.onmicrosoft.com/B2C_1_signupandin/oauth2/v2.0/authorize";
    public string tokenEndpoint = "https://newleafms.b2clogin.com/newleafms.onmicrosoft.com/B2C_1_signupandin/oauth2/v2.0/token";

    public async void doOAuth()
    {
        // Generates state and PKCE values.
        string _state = randomDataBase64url(32);
        string _codeVerifier = randomDataBase64url(32);
        string _codeChallenge = base64urlencodeNoPadding(sha256(_codeVerifier));
        const string code_challenge_method = "S256";

        // Creates an HttpListener to listen for requests on that redirect URI.
        var http = new Http();
        http.Start();

        // Creates the OAuth 2.0 authorization request.
        string authorizationRequest = string.Format("{0}?response_type=code&scope=offline_access {6}&redirect_uri={1}&client_id={2}&state={3}&code_challenge={4}&code_challenge_method={5}",
            authorizationEndpoint,
            System.Uri.EscapeDataString(http.Url),
            clientID,
            _state,
            _codeChallenge,
            code_challenge_method,
            clientID);

        // Opens request in the browser.
        Process.Start( new ProcessStartInfo { FileName = authorizationRequest, UseShellExecute = true } );
        // System.Diagnostics.Process.Start(authorizationRequest);

        // Waits for the OAuth authorization response.
        var context = await http.httpListener.GetContextAsync();

        // Brings the Console to Focus.
        // BringConsoleToFront();

        // Sends an HTTP response to the browser.
        var response = context.Response;
        string responseString = string.Format("<html><head></head><body>Please return to the app.</body></html>");
        var buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
        response.ContentLength64 = buffer.Length;
        var responseOutput = response.OutputStream;
        Task responseTask = responseOutput.WriteAsync(buffer, 0, buffer.Length).ContinueWith((task) =>
        {
            responseOutput.Close();
            http.Stop();
            UnityEngine.Debug.Log("HTTP server stopped.");
        });

        // Checks for errors.
        if (context.Request.QueryString.Get("error") != null)
        {
            output(String.Format("OAuth authorization error: {0}.", context.Request.QueryString.Get("error")));
            return;
        }
        Debug.Log(context.Request.QueryString);
        
        if (context.Request.QueryString.Get("code") == null
            || context.Request.QueryString.Get("state") == null)
        {
            output("Malformed authorization response. " + context.Request.QueryString.AllKeys.ToString());
            return;
        }

        // extracts the code
        var code = context.Request.QueryString.Get("code");
        var incoming_state = context.Request.QueryString.Get("state");

        // Compares the receieved state to the expected value, to ensure that
        // this app made the request which resulted in authorization.
        if (incoming_state != _state)
        {
            output(String.Format("Received request with invalid state ({0})", incoming_state));
            return;
        }
        output("Authorization code: " + code);

        // Starts the code exchange at the Token Endpoint.
        performCodeExchange(code, _codeVerifier, http.Url);
    }

    async void performCodeExchange(string code, string code_verifier, string redirectURI)
    {
        output("Exchanging code for tokens...");

        // builds the  request
        string tokenRequestBody = string.Format("code={0}&redirect_uri={1}&client_id={2}&code_verifier={3}&scope=&grant_type=authorization_code",
            code,
            System.Uri.EscapeDataString(redirectURI),
            clientID,
            code_verifier
            );

        // sends the request
        HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(tokenEndpoint);
        tokenRequest.Method = "POST";
        tokenRequest.ContentType = "application/x-www-form-urlencoded";
        //tokenRequest.Accept = "Accept=application/json;charset=UTF-8";
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
                UnityEngine.Debug.Log("responseText");
                UnityEngine.Debug.Log(responseText);
                UnityEngine.Debug.Log("responseText");

                // converts to dictionary
                Dictionary<string, string> tokenEndpointDecoded = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);

                string access_token = tokenEndpointDecoded["access_token"];
                output(access_token);
            }
        }
        catch (WebException ex)
        {
            if (ex.Status == WebExceptionStatus.ProtocolError)
            {
                var response = ex.Response as HttpWebResponse;
                if (response != null)
                {
                    output("HTTP: " + response.StatusCode);
                    using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                    {
                        // reads response body
                        string responseText = await reader.ReadToEndAsync();
                        output(responseText);
                    }
                }

            }
        }
    }


    /// <summary>
    /// Appends the given string to the on-screen log, and the debug console.
    /// </summary>
    /// <param name="output">string to be appended</param>
    public void output(string output)
    {
        UnityEngine.Debug.Log(output);
    }

    /// <summary>
    /// Returns URI-safe data with a given input length.
    /// </summary>
    /// <param name="length">Input length (nb. output will be longer)</param>
    /// <returns></returns>
    public static string randomDataBase64url(uint length)
    {
        RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        byte[] bytes = new byte[length];
        rng.GetBytes(bytes);
        return base64urlencodeNoPadding(bytes);
    }

    /// <summary>
    /// Returns the SHA256 hash of the input string.
    /// </summary>
    /// <param name="inputStirng"></param>
    /// <returns></returns>
    public static byte[] sha256(string inputStirng)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(inputStirng);
        SHA256Managed sha256 = new SHA256Managed();
        return sha256.ComputeHash(bytes);
    }

    /// <summary>
    /// Base64url no-padding encodes the given input buffer.
    /// </summary>
    /// <param name="buffer"></param>
    /// <returns></returns>
    public static string base64urlencodeNoPadding(byte[] buffer)
    {
        string base64 = Convert.ToBase64String(buffer);

        // Converts base64 to base64url.
        base64 = base64.Replace("+", "-");
        base64 = base64.Replace("/", "_");
        // Strips padding.
        base64 = base64.Replace("=", "");

        return base64;
    }

    // Hack to bring the Console window to front.
    // ref: http://stackoverflow.com/a/12066376

    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    public void BringConsoleToFront()
    {
        SetForegroundWindow(GetConsoleWindow());
    }
    }
}