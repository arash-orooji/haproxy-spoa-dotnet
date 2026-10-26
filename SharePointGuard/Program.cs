using System.Net;
using System.Net.Sockets;
using HAProxy.StreamProcessingOffload.Agent;
using HAProxy.StreamProcessingOffload.Agent.Actions;
using HAProxy.StreamProcessingOffload.Agent.Payloads;
using SharePointGuard;

const string MessageName = "sharepoint-guard";

int port = int.TryParse(Environment.GetEnvironmentVariable("SPGUARD_PORT"), out int p) ? p : 12345;
string rulesPath = Environment.GetEnvironmentVariable("SPGUARD_RULES")
    ?? Path.Combine(AppContext.BaseDirectory, "rules.json");
bool debug = Environment.GetEnvironmentVariable("SPGUARD_DEBUG") is "1" or "true";

var guard = new Guard(RuleSet.Load(rulesPath));
Log($"Loaded {guard.RuleSet.Rules.Count(r => r.Enabled)} enabled rules from {rulesPath}");

var frameProcessor = new FrameProcessor
{
    EnableLogging = debug,
    LogFunc = Log,
};

using var shutdown = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; shutdown.Cancel(); };
AppDomain.CurrentDomain.ProcessExit += (_, _) => shutdown.Cancel();

var listener = new TcpListener(IPAddress.Any, port);
listener.Start();
Log($"SharePoint Guard SPOA listening on 0.0.0.0:{port}");

try
{
    while (!shutdown.IsCancellationRequested)
    {
        TcpClient client = await listener.AcceptTcpClientAsync(shutdown.Token);
        _ = Task.Run(() => HandleConnectionAsync(client));
    }
}
catch (OperationCanceledException)
{
    // shutting down
}
finally
{
    listener.Stop();
}

async Task HandleConnectionAsync(TcpClient client)
{
    using (client)
    {
        try
        {
            NetworkStream stream = client.GetStream();
            await using CancellationTokenRegistration registration =
                shutdown.Token.Register(() => frameProcessor.CancelStreamAsync(stream).AsTask().Wait());

            await frameProcessor.HandleStreamAsync(stream, notifyFrame =>
            {
                var actions = new List<SpoeAction>();
                var messages = ((ListOfMessagesPayload)notifyFrame.Payload).Messages;

                foreach (SpoeMessage message in messages.Where(m => m.Name == MessageName))
                {
                    RequestInfo request = ToRequestInfo(message);
                    Verdict verdict = guard.Evaluate(request);

                    if (verdict.Blocked)
                    {
                        Log($"BLOCK rule={verdict.RuleId} src={request.Source} {request.Method} {request.Path}{(string.IsNullOrEmpty(request.Query) ? "" : "?" + request.Query)}");
                        actions.Add(new SetVariableAction(VariableScope.Transaction, "block", new TypedData(DataType.Int32, 1)));
                        actions.Add(new SetVariableAction(VariableScope.Transaction, "rule", new TypedData(DataType.String, verdict.RuleId!)));
                    }
                    else if (debug)
                    {
                        Log($"ALLOW src={request.Source} {request.Method} {request.Path}");
                    }
                }

                return new ValueTask<IList<SpoeAction>>(actions);
            });
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or SocketException)
        {
            // HAProxy closed the connection.
        }
        catch (Exception ex)
        {
            Log($"Connection error: {ex}");
        }
    }
}

static RequestInfo ToRequestInfo(SpoeMessage message)
{
    string? Arg(string name) =>
        message.Args.TryGetValue(name, out TypedData? data) && data.Value is not null ? data.Value.ToString() : null;

    IPAddress? source = IPAddress.TryParse(Arg("src"), out IPAddress? ip)
        ? (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip)
        : null;

    return new RequestInfo(
        Method: Arg("method") ?? "GET",
        Path: Arg("path") ?? "/",
        Query: Arg("query"),
        Referer: Arg("referer"),
        Authorization: Arg("authorization"),
        ProofToken: Arg("prooftoken"),
        Source: source);
}

static void Log(string message) => Console.WriteLine($"{DateTimeOffset.UtcNow:O} {message}");
