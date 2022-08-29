using System;
using System.Net;
using System.Threading;

namespace Newleaf.Oauth
{
    public class Http
    {
        public readonly HttpListener httpListener = new HttpListener();
        public string Url;

        public Http (int _port = 60429, bool _secure = false)
        {
            var _http = _secure ? "https" : "http";
            Url = $"{_http}://localhost:{_port}/";
            httpListener.Prefixes.Add(Url);
        }

        public void Start ()
        {
            httpListener.Start();
            Console.WriteLine("Listening...");
        } 
        public void Stop ()
        {
            httpListener.Stop();
        } 
    }
}