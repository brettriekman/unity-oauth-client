using Newleaf.Http.Oauth;
using UnityEngine;
using ILogger = Newleaf.Http.Oauth.ILogger;

public class UnityPkceLogin : MonoBehaviour
{
    // Start is called before the first frame update
    public class Logger : ILogger
    {
        public void Log (string _message)
        {
            Debug.Log(_message);
        }
    }
    
    void Start()
    {
        var server = new OauthLoginServer();
        server.HandleAccessToken += SetAccessToken;
        server.pkceLogin();
    }

    public void SetAccessToken (object sender, string _accessToken)
    {
        Debug.Log($"access token: {_accessToken}");
    }

}
