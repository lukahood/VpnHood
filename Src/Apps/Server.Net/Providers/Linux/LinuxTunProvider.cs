using Microsoft.Win32.SafeHandles;
using PacketDotNet;
using System.Buffers;
using System.Runtime.InteropServices;
using VpnHood.Core.Server.Abstractions;

namespace VpnHood.App.Server.Providers.Linux;

internal class LinuxTunProvider : ITunProvider, IDisposable
{
    public event EventHandler<IPPacket>? OnPacketReceived;

    private readonly FileStream _deviceStream;
    private const string DefaultDeviceName = "tun0";
    private const string DefaultDevicePath = "/dev/net/tun";
    private bool _disposed;
    private static readonly ArrayPool<byte> BufferPool = ArrayPool<byte>.Shared;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public LinuxTunProvider()
    {
        var tunFd = OpenTunDevice(DefaultDeviceName, DefaultDevicePath);
        _deviceStream = new FileStream(new SafeFileHandle(tunFd, ownsHandle: true), FileAccess.ReadWrite);

        // Start listening for packets asynchronously
        Task.Run(StartListening);
    }

    public async Task SendPacket(IPPacket ipPacket)
    {
        if (_deviceStream == null)
            throw new InvalidOperationException("TUN device is not initialized.");

        var packetBytes = ipPacket.Bytes;
        await _writeLock.WaitAsync();
        try {
            await _deviceStream.WriteAsync(packetBytes, 0, packetBytes.Length);
            Console.WriteLine("Packet sent.");
        }
        finally {
            _writeLock.Release();
        }
    }

    private async Task StartListening()
    {
        var buffer = BufferPool.Rent(1500); // MTU size
        try {
            while (true) {
                var bytesRead = await _deviceStream.ReadAsync(buffer, 0, buffer.Length);
                if (bytesRead > 20) // Minimum IP header size
                {
                    var ipPacket = Packet.ParsePacket(LinkLayers.Raw, buffer).Extract<IPPacket>();
                    OnPacketReceived?.Invoke(this, ipPacket);
                }
            }
        }
        finally {
            BufferPool.Return(buffer);
        }
    }

    private int OpenTunDevice(string deviceName, string devicePath)
    {
        // ReSharper disable once InconsistentNaming
        const int IFF_TUN = 0x0001;  // TUN device (Layer 3)
        // ReSharper disable once InconsistentNaming
        const int IFF_NO_PI = 0x1000; // No packet information
        // ReSharper disable once IdentifierTypo
        // ReSharper disable once InconsistentNaming
        const int TUNSETIFF = 0x400454ca; // ioctl request code for TUN device
        // ReSharper disable once IdentifierTypo
        // ReSharper disable once InconsistentNaming
        const int ORdwr = 0x0002; // Open for read/write

        // Open the TUN device file
        var fd = Syscall.open(devicePath, ORdwr);
        if (fd < 0)
            throw new InvalidOperationException("Failed to open TUN device.");

        // Configure the device
        var ifr = new Ifreq {
            ifr_name = deviceName,
            ifr_flags = IFF_TUN | IFF_NO_PI
        };

        var ioctlResult = Syscall.ioctl(fd, TUNSETIFF, ref ifr);
        if (ioctlResult < 0) {
            Console.WriteLine($"Error configuring TUN device: {Marshal.GetLastWin32Error()}");
            Syscall.close(fd);
            return -1;
        }

        return fd;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct Ifreq
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string ifr_name; // Interface name
        public ushort ifr_flags; // Flags (e.g., IFF_TUN)
    }

    private static class Syscall
    {
        [DllImport("libc", SetLastError = true)]
        public static extern int open(string pathname, int flags);

        [DllImport("libc", SetLastError = true)]
        public static extern int ioctl(int fd, uint request, ref Ifreq ifr);

        [DllImport("libc", SetLastError = true)]
        public static extern int close(int fd);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed) {
            if (disposing) {
                // Dispose managed resources
                _deviceStream.Dispose();
            }

            // Dispose unmanaged resources (e.g., close the TUN device)
            if (_deviceStream.SafeFileHandle is { IsInvalid: false }) {
                Syscall.close(_deviceStream.SafeFileHandle.DangerousGetHandle().ToInt32());
            }

            _disposed = true;
        }
    }

    ~LinuxTunProvider()
    {
        Dispose(false);
    }
}

