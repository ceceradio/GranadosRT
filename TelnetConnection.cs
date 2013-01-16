using GranadosRT.Routrek.SSHC;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.Resources;
using Windows.Networking.Sockets;
using System.Runtime.InteropServices.WindowsRuntime;

namespace GranadosRT
{
    public sealed class TelnetConnection : SSHConnection
    {

        private static ResourceLoader resLoader = new Windows.ApplicationModel.Resources.ResourceLoader();
        private SSHConnectionParameter _param;
        private ISSHConnectionEventReceiver _eventReceiver;
        private TelnetChannel _channel_entry = null;
        private bool _autoDisconnect;
        private StreamSocket socket = null;


        public TelnetConnection(SSHConnectionParameter param, ISSHConnectionEventReceiver r, StreamSocket s) {
            _param = (SSHConnectionParameter)param.Clone();
            _eventReceiver = r;
            _autoDisconnect = true;
            socket = s;
		}

        public SSHConnectionInfo ConnectionInfo()
        {
            throw new NotImplementedException();
        }

        public bool Available()
        {
            return (socket != null);
        }

        public SSHConnectionParameter Param()
        {
            return _param;
        }

        public AuthenticationResult AuthenticationResult()
        {
            return GranadosRT.Routrek.SSHC.AuthenticationResult.Success;
        }

        public IByteArrayHandler PacketBuilder()
        {
            throw new NotImplementedException();
        }

        public ISSHConnectionEventReceiver EventReceiver()
        {
            return _eventReceiver;
        }

        public int ChannelCount()
        {
            return (_channel_entry == null) ? 0 : 1;
        }

        public bool IsClosed()
        {
            return false;
        }

        public bool AutoDisconnect()
        {
            return _autoDisconnect;
        }

        public AuthenticationResult DoConnect(AbstractSocket target)
        {
            return GranadosRT.Routrek.SSHC.AuthenticationResult.Success;
        }

        public void Disconnect(string msg)
        {
            throw new NotImplementedException();
        }

        public void RegisterChannel(int local_id, SSHChannel ch)
        {
            throw new NotImplementedException();
        }

        public void UnregisterChannelEventReceiver(int id)
        {
            throw new NotImplementedException();
        }

        public SSHChannel OpenShell(ISSHChannelEventReceiver receiver)
        {
            _channel_entry = new TelnetChannel(this, socket, receiver);
            TelnetPacketBuilder pb = new TelnetPacketBuilder(receiver);
            PlainSocket ps = new PlainSocket(socket, pb);
            ps.RepeatAsyncRead();
            return _channel_entry;
        }

        public SSHChannel ForwardPort(ISSHChannelEventReceiver receiver, string remote_host, int remote_port, string originator_host, int originator_port)
        {
            throw new NotImplementedException();
        }

        public void ListenForwardedPort(string allowed_host, int bind_port)
        {
            throw new NotImplementedException();
        }

        public void CancelForwardedPort(string host, int port)
        {
            throw new NotImplementedException();
        }

        public void Close()
        {
            socket.Dispose();
        }

        public void SendIgnorableData(string msg)
        {
            //Do nothing
        }

        public static TelnetConnection Connect(SSHConnectionParameter param, ISSHConnectionEventReceiver receiver, StreamSocket underlying_socket) {
            return new TelnetConnection(param, receiver, underlying_socket);
        }
    }
    class TelnetChannel : SSHChannel
    {
        TelnetConnection _parent;
        StreamSocket _socket;
        ISSHChannelEventReceiver _receiver;
        public TelnetChannel(TelnetConnection parent, StreamSocket socket, ISSHChannelEventReceiver r)
        {
            _parent = parent;
            _socket = socket;
            _receiver = r;
        }
        public void ResizeTerminal(int width, int height, int pixel_width, int pixel_height)
        {
            //throw new NotImplementedException();
            //Do nothing
        }

        public void Transmit(byte[] data)
        {
            _socket.OutputStream.WriteAsync(data.AsBuffer()).AsTask().Wait();
        }

        public void Transmit(byte[] data, int offset, int length)
        {
            _socket.OutputStream.WriteAsync(data.AsBuffer(offset,length)).AsTask().Wait();
        }

        public void SendEOF()
        {
            //throw new NotImplementedException();
            _socket.Dispose();
        }

        public void Close()
        {
            _socket.Dispose();
        }

        public int LocalChannelID()
        {
            return 1;
        }

        public int RemoteChannelID()
        {
            return 1;
        }

        public SSHConnection Connection()
        {
            return _parent;
        }

        public ChannelType Type()
        {
            return ChannelType.Shell;
        }
    }
    internal class TelnetPacketBuilder : IByteArrayHandler
    {
        ISSHChannelEventReceiver _handler;
        public TelnetPacketBuilder(ISSHChannelEventReceiver handler)
        {
            this._handler = handler;
        }
        public void OnData(byte[] data, int offset, int length)
        {
            _handler.OnData(data, offset, length);
        }

        public void OnClosed()
        {
            _handler.OnChannelClosed();
        }

        public void OnError(Exception error, string msg)
        {
            _handler.OnChannelError(error, msg);
        }
    }
}
