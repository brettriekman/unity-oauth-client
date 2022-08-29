using Newleaf.Oauth;
using UnityEngine;

public class test : MonoBehaviour
{
    // Start is called before the first frame update
    void Start()
    {
        Debug.Log("started");
        var test = new OauthClient();
        test.doOAuth();
    }

    // Update is called once per frame
    void Update()
    {
        
    }
}
