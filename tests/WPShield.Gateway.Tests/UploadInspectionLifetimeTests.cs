using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using WPShield.Core;

namespace WPShield.Gateway.Tests;

public sealed class UploadInspectionLifetimeTests
{
    [Theory]
    [InlineData(ProtectionMode.Block, false)]
    [InlineData(ProtectionMode.Monitor, false)]
    [InlineData(ProtectionMode.Monitor, true)]
    public async Task ForwardedBody_HoldsSlotUntilDisposed(ProtectionMode mode, bool malformed)
    {
        using var limiter = new ConcurrentInspectionLimiter(1);
        var service = new UploadInspectionService(new InspectionEngine([]), new MultipartInspectionReader(), limiter);
        var first = await EvaluateAsync(service, mode, malformed);
        using var body = Assert.IsType<PooledRequestBuffer>(first.Body);

        // Inspection finished, but forwarding still owns the body. A second request must not buffer.
        var second = await EvaluateAsync(service, mode, false);
        using var unexpectedBody = second.Body;
        Assert.Null(second.Body);
        if (mode == ProtectionMode.Block)
        {
            Assert.Equal(StatusCodes.Status429TooManyRequests, second.Rejection?.StatusCode);
        }
        else
        {
            Assert.Null(second.Rejection);
        }

        Assert.Equal(1, limiter.CurrentCount);
        body.Dispose();
        body.Dispose();
        Assert.Equal(0, limiter.CurrentCount);
        var third = await EvaluateAsync(service, mode, false);
        using var nextBody = Assert.IsType<PooledRequestBuffer>(third.Body);
        Assert.Null(third.Rejection);
    }

    [Fact]
    public async Task RejectedBody_ReleasesSlot()
    {
        using var limiter = new ConcurrentInspectionLimiter(1);
        var service = new UploadInspectionService(new InspectionEngine([]), new MultipartInspectionReader(), limiter);
        var rejected = await EvaluateAsync(service, ProtectionMode.Block, true);
        Assert.Equal(StatusCodes.Status415UnsupportedMediaType, rejected.Rejection?.StatusCode);
        Assert.Null(rejected.Body);
        Assert.Equal(0, limiter.CurrentCount);
        var next = await EvaluateAsync(service, ProtectionMode.Block, false);
        using var body = Assert.IsType<PooledRequestBuffer>(next.Body);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedRead_ReleasesSlot(bool cancelled)
    {
        using var limiter = new ConcurrentInspectionLimiter(1);
        var service = new UploadInspectionService(new InspectionEngine([]), new MultipartInspectionReader(), limiter);
        using var source = new FailingStream(cancelled);
        var error = await Record.ExceptionAsync(() => EvaluateAsync(service, ProtectionMode.Block, false,
            source, new CancellationToken(cancelled)));
        if (cancelled)
        {
            Assert.IsAssignableFrom<OperationCanceledException>(error);
        }
        else
        {
            Assert.IsType<IOException>(error);
        }

        Assert.Equal(0, limiter.CurrentCount);
        var next = await EvaluateAsync(service, ProtectionMode.Block, false);
        using var body = Assert.IsType<PooledRequestBuffer>(next.Body);
    }

    private sealed class FailingStream(bool cancelled) : MemoryStream
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            cancelled
                ? ValueTask.FromCanceled<int>(cancellationToken)
                : ValueTask.FromException<int>(new IOException("Synthetic read failure."));
    }

    private static async Task<UploadInspectionDecision> EvaluateAsync(
        UploadInspectionService service, ProtectionMode mode, bool malformed,
        Stream? overrideSource = null, CancellationToken cancellationToken = default)
    {
        var bytes = Encoding.ASCII.GetBytes(
            "--test-boundary\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nsynthetic\r\n--test-boundary--\r\n");
        using var source = new MemoryStream(bytes);
        var context = new DefaultHttpContext();
        context.Request.ContentType = malformed ? "multipart/form-data" : "multipart/form-data; boundary=test-boundary";
        context.Request.ContentLength = bytes.Length;
        context.Request.Body = new RequestBodyLimitStream(overrideSource ?? source, 1024);
        return await service.EvaluateAsync(context, new SiteOptions
        {
            Id = "wordpress-one",
            Mode = mode,
            Hosts = ["wordpress-one.example"],
            Destination = new Uri("http://127.0.0.1:8081")
        },
            new GatewayOptions { MaximumRequestBytes = 1024 }, new MultipartInspectionOptions(),
            NullLogger.Instance, cancellationToken);
    }
}
