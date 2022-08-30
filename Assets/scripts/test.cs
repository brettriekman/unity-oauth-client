using Newleaf.Http.Oauth;
using UnityEngine;
using ILogger = Newleaf.Http.Oauth.ILogger;

public class test : MonoBehaviour
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
        var test = new OauthLoginServer(new Logger());
        test.HandleAccessToken += SetAccessToken;
        test.pkceLogin();
    }

    public void SetAccessToken (object sender, string _accessToken)
    {
        Debug.Log($"access token: {_accessToken}");
    }

    // Update is called once per frame
    void Update()
    {
        
    }
}
