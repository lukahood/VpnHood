using Microsoft.Win32.SafeHandles;
using PacketDotNet;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using VpnHood.Core.Server.Abstractions;
using VpnHood.Core.Tunneling;
using System.Diagnostics;

namespace VpnHood.App.Server.Providers.Linux;

internal class LinuxTunProvider : ITunProvider
{
    private readonly ILogger _logger;
    public event EventHandler<IPPacket>? OnPacketReceived;

    private readonly FileStream _tunReader;
    private readonly FileStream _tunWriter;
    private const string DefaultDeviceName = "tun0";
    private const string DefaultDevicePath = "/dev/net/tun";
    private bool _disposed;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    private LinuxTunProvider(ILogger logger)
    {
        _logger = logger;
        var tunFd = OpenTunDevice(DefaultDeviceName, DefaultDevicePath);
        _tunReader = new FileStream(new SafeFileHandle(tunFd, ownsHandle: true), FileAccess.Read);
        _tunWriter = new FileStream(new SafeFileHandle(tunFd, ownsHandle: true), FileAccess.Write);

        // Start listening for packets asynchronously
        _logger.LogInformation("Starting TUN listener...");
        _ = StartListening();
    }

    public static async Task<LinuxTunProvider> Create(ILogger logger)
    {
        logger.LogInformation("Creating tun provider...");
        await Init(logger);
        var tunProvider = new LinuxTunProvider(logger);
        return tunProvider;
    }

    public async Task SendPacket(IPPacket ipPacket)
    {
        if (_tunWriter == null)
            throw new InvalidOperationException("TUN device is not initialized.");

        var packetBytes = ipPacket.Bytes;
        await _writeLock.WaitAsync();
        try {
            Console.WriteLine($"packet aaaaa: {ipPacket.TotalLength}");
            await _tunWriter.WriteAsync(packetBytes, 0, packetBytes.Length);
        }
        finally {
            _writeLock.Release();
        }
    }

    private async Task StartListening()
    {
        var buffer = new byte[0xffff]; // MTU size
        while (true) {
            var bytesRead = await _tunReader.ReadAsync(buffer, 0, buffer.Length);

            if (bytesRead == 0)
                break;

            if (bytesRead < 20)
                continue; // Minimum IP header size

            try {
                var ipPacket = Packet.ParsePacket(LinkLayers.Raw, buffer).Extract<IPPacket>();
                OnPacketReceived?.Invoke(this, ipPacket);
            }
            catch (Exception ex) {
                _logger.LogError(GeneralEventId.Packet, ex, "TUN can not parse the packet.");
            }
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
            Syscall.close(fd);
            throw new Exception($"Could not configure TUN device. LastError: {Marshal.GetLastWin32Error()}. IoctlResult: {ioctlResult} ");
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
        if (_disposed)
            return;

        _disposed = true;

        _tunWriter.Dispose();
        if (_tunWriter.SafeFileHandle is { IsInvalid: false })
            Syscall.close(_tunWriter.SafeFileHandle.DangerousGetHandle().ToInt32());

        _tunReader.Dispose();
        if (_tunReader.SafeFileHandle is { IsInvalid: false })
            Syscall.close(_tunReader.SafeFileHandle.DangerousGetHandle().ToInt32());
    }

    private static async Task Init(ILogger logger)
    {
        const string tunInterface = "tun0";

        // Detect main network interface
        var mainInterface = GetMainNetworkInterface();
        if (string.IsNullOrEmpty(mainInterface)) {
            logger.LogError("No active network interface found.");
            return;
        }

        // Remove existing tunnel interface
        logger.LogTrace($"Removing existing {tunInterface} (if any)...");
        await LinuxUtils.ExecuteCommandAsync($"ip tuntap del dev {tunInterface} mode tun");

        // Enable IP forwarding
        logger.LogTrace("Enabling IP forwarding.");
        await LinuxUtils.ExecuteCommandAsync("sysctl -w net.ipv4.ip_forward=1");

        // Configure NAT with iptables
        logger.LogTrace("Setting up NAT with iptables...");
        await LinuxUtils.ExecuteCommandAsync($"iptables -t nat -A POSTROUTING -s 10.10.0.0/8 -o {mainInterface} -j MASQUERADE");

        // Create and configure tun interface
        logger.LogTrace($"Creating tunnel interface {tunInterface}...");
        await LinuxUtils.ExecuteCommandAsync($"ip tuntap add dev {tunInterface} mode tun");

        logger.LogTrace($"Bringing up {tunInterface}...");
        await LinuxUtils.ExecuteCommandAsync($"ip link set up dev {tunInterface}");

        logger.LogTrace($"Assigning IP to {tunInterface}...");
        await LinuxUtils.ExecuteCommandAsync($"ifconfig {tunInterface} 10.10.0.1 netmask 255.255.0.0 up");

        logger.LogTrace("Tunnel interface configured successfully!");
    }

    private static string GetMainNetworkInterface()
    {
        try {
            var psi = new ProcessStartInfo {
                FileName = "/bin/bash",
                Arguments = "-c \"ip route | grep default | awk '{print $5}'\"",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = new Process();
            process.StartInfo = psi;
            process.Start();
            var output = process.StandardOutput.ReadToEnd().Trim();
            process.WaitForExit();

            if (!string.IsNullOrWhiteSpace(output))
                return output;
        }
        catch (Exception ex) {
            Console.WriteLine($"[ERROR] Failed to get main network interface: {ex.Message}");
        }

        return string.Empty;
    }
}

