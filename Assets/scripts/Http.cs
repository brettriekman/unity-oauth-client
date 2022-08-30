using System;
using System.Net;

namespace Newleaf.Http
{
    public class HttpServer
    {
        public readonly HttpListener listener = new ();
        public string Url;
        public event EventHandler<HttpListenerResponse> ResponseReceived;

        protected virtual void OnResponseReceived (HttpListenerResponse _e)
        {
            ResponseReceived?.Invoke(this, _e);
        }

        public HttpServer (string _url= "localhost", int _port = 60429, bool _secure = false)
        {
            var _http = _secure ? "https" : "http";
            Url = $"{_http}://{_url}:{_port}/";
            listener.Prefixes.Add(Url);
        }

        public void Start ()
        {
            listener.Start();
        }

        public void Stop ()
        {
            listener.Stop();
            listener.Close();
        } 
    }
}