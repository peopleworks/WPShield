namespace WPShield.Gateway;

internal sealed class RequestBodyLimitStream(Stream inner, long maximumBytes) : Stream
{
    private long _bytesRead;

    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => _bytesRead;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var allowedCount = GetAllowedReadSize(count);
        var read = inner.Read(buffer, offset, allowedCount);
        return RecordRead(read);
    }

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        var allowedCount = GetAllowedReadSize(buffer.Length);
        var read = await inner.ReadAsync(buffer[..allowedCount], cancellationToken);
        return RecordRead(read);
    }

    public override Task<int> ReadAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken)
    {
        return ReadArrayAsync(buffer, offset, count, cancellationToken);
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
    }

    private async Task<int> ReadArrayAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken)
    {
        var allowedCount = GetAllowedReadSize(count);
        var read = await inner.ReadAsync(buffer.AsMemory(offset, allowedCount), cancellationToken);
        return RecordRead(read);
    }

    private int GetAllowedReadSize(int requestedCount)
    {
        if (requestedCount == 0)
        {
            return 0;
        }

        var remaining = maximumBytes - _bytesRead;
        return (int)Math.Min(requestedCount, Math.Max(1, remaining + 1));
    }

    private int RecordRead(int read)
    {
        if (read == 0)
        {
            return 0;
        }

        _bytesRead += read;
        if (_bytesRead > maximumBytes)
        {
            throw new RequestBodyTooLargeException();
        }

        return read;
    }
}

internal sealed class RequestBodyTooLargeException : IOException;
