using System.Net;

namespace AuthAndRefreshTokenDemo.Middleware
{
    public class RequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger _logger;

        public RequestLoggingMiddleware(RequestDelegate next, ILoggerFactory loggerFactory)
        {
            _next = next;
            _logger = loggerFactory.CreateLogger<RequestLoggingMiddleware>();
        }

        public async Task Invoke(HttpContext context)
        {
            try
            {
                _logger.LogInformation("Request {method} {requestUrl}", context.Request?.Method, context.Request?.Path.Value);
                await _next(context);
            }
            finally
            {
                var statusCode = (HttpStatusCode)(context.Response?.StatusCode ?? 0);
                _logger.LogInformation("Response {method} {requestUrl} => {statusCode}-{statusCodeName}", context.Request?.Method, context.Request?.Path.Value, (int)statusCode, statusCode);
            }
        }
    }
}
