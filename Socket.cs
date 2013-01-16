using System;
using System.Text;
using System.IO;
//using System.Net.Sockets;
using Windows.Networking.Sockets;
using Windows.Networking;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using System.Threading.Tasks;
using Windows.Storage.Streams;


namespace GranadosRT.Routrek.SSHC
{
	public enum ReceiverState {
		Ready,
		Closed,
		Error
	}

	public interface IHandlerBase {
		void OnClosed();
		void OnError(Exception error, string msg);
	}
	public interface IByteArrayHandler : IHandlerBase {
		//IAsyncAction OnData([ReadOnlyArray()] byte[] data, int offset, int length);
        void OnData([ReadOnlyArray()] byte[] data, int offset, int length);
	}
	internal interface IStringHandler : IHandlerBase {
		void OnString(string data);
	}


	public sealed class ProtocolNegotiationHandler : IByteArrayHandler {
		protected string _serverVersion;
		protected SSHConnectionParameter _param;
		protected string _endOfLine;

        public void SetClosed()
        {
            _state = ReceiverState.Closed;
            _event.Set();
        }
        public void SetError(string msg)
        {
            _errorMessage = msg;
            _state = ReceiverState.Error;
            _event.Set();
        }
        public void SetReady()
        {
            _state = ReceiverState.Ready;
            _event.Set();
        }

        protected ManualResetEvent _event;
        protected ReceiverState _state;
        protected string _errorMessage;

        internal WaitHandle WaitHandle
        {
            get
            {
                return _event;
            }
        }
        public ReceiverState State
        {
            get
            {
                return _state;
            }
        }
        public string ErrorMessage
        {
            get
            {
                return _errorMessage;
            }
        }

        public void Wait()
        {
            _event.WaitOne();
            _event.Reset();
        }
        /// <summary>
        /// STart new class
        /// </summary>
        /// <param name="param"></param>

		public ProtocolNegotiationHandler(SSHConnectionParameter param) {
            _event = new ManualResetEvent(false);
			_param = param;
			_errorMessage = Strings.GetString("NotSSHServer");
		}

		public string ServerVersion {
			get {
				return _serverVersion;
			}
		}
		public string EOL {
			get {
				return _endOfLine;
			}
		}

        //public IAsyncAction OnData([ReadOnlyArray()]  byte[] data, int offset, int length)
        public void OnData([ReadOnlyArray()]  byte[] data, int offset, int length)
        {
            //return Task.Run(() =>
            //{
                try
                {
                    //the specification claims the version string ends with CRLF, however some servers send LF only
                    if (length <= 2 || data[offset + length - 1] != 0x0A)
                        //throw new Exception(Strings.GetString("NotSSHServer"));
                        throw new Exception(Strings.GetString("NotSSHServer"));
                    //Debug.WriteLine(String.Format("receiveServerVersion len={0}",len));
                    string sv = Encoding.UTF8.GetString(data, offset, length);
                    _serverVersion = sv.Trim();
                    _endOfLine = sv.EndsWith("\r\n") ? "\r\n" : "\n"; //quick hack

                    //check compatibility
                    int a = _serverVersion.IndexOf('-');
                    if (a == -1)
                        //throw new Exception("Format of server version is invalid");
                        throw new Exception("Format of server version is invalid");
                    int b = _serverVersion.IndexOf('-', a + 1);
                    if (b == -1)
                        //throw new Exception("Format of server version is invalid");
                        throw new Exception("Format of server version is invalid");
                    int comma = _serverVersion.IndexOf('.', a, b - a);
                    if (comma == -1)
                        //throw new Exception("Format of server version is invalid");
                        throw new Exception("Format of server version is invalid");

                    int major = Int32.Parse(_serverVersion.Substring(a + 1, comma - a - 1));
                    int minor = Int32.Parse(_serverVersion.Substring(comma + 1, b - comma - 1));

                    if (_param.Protocol == SSHProtocol.SSH1)
                    {
                        if (major != 1) throw new Exception("The protocol version of server is not compatible for SSH1");
                    }
                    else
                    {
                        if (major >= 3 || major <= 0 || (major == 1 && minor != 99))
                            //throw new Exception("The protocol version of server is not compatible with SSH2");
                            throw new Exception("The protocol version of server is not compatible with SSH2");
                    }

                    this.SetReady();
                }
                catch (Exception ex)
                {
                    OnError(ex, ex.Message);
                }
            //}).AsAsyncAction();
		}

		public void OnError(Exception error, string msg) {
			SetError(msg);
		}
		public void OnClosed() {
			SetClosed();
		}
	}

	//System.IO.Socket‚ÆIChannelEventReceiver‚ð’ŠÛ‰»‚·‚é
	public interface AbstractSocket {
		
        void SetHandler(IByteArrayHandler h);

		void Write([ReadOnlyArray()]byte[] data, int offset, int length);
		void WriteByte(byte data);
		void Flush();
		void Close();
		bool DataAvailable { get; }
	}

	internal class PlainSocket : AbstractSocket {
		private StreamSocket _socket;
		private byte[] _buf;
		private bool _closed;

        protected IByteArrayHandler _handler;

		internal PlainSocket(StreamSocket s, IByteArrayHandler h) {
            _handler = h;
			_socket = s;
			_buf = new byte[0x1000];
			_closed = false;
		}
        public void SetHandler(IByteArrayHandler h)
        {
            _handler = h;
        }

        public void Write([ReadOnlyArray()] byte[] data, int offset, int length)
        {
            var waitTask = _socket.OutputStream.WriteAsync(data.AsBuffer());
            waitTask.AsTask().Wait();
			//_socket.Send(data, offset, length, SocketFlags.None);
		}
		public void WriteByte(byte data) {
			byte[] t = new byte[1];
			t[0] = data;
			//_socket.Send(t, 0, 1, SocketFlags.None);
            this.Write(t, 0, 1);
		}

		public void Flush() {
            var flushTask = _socket.OutputStream.FlushAsync();
            flushTask.AsTask().Wait();
		}
        public void Close()
        {
			_socket.Dispose();
			_closed = true;
		}
		
		internal async void RepeatAsyncRead() {

            //_socket.InputStream.ReadAsync(_buf.AsBuffer(), (uint)_buf.Length, Windows.Storage.Streams.InputStreamOptions.Partial).Completed = RepeatCallback;
            await Task.Run( async () => {
                while (true) {
                    try {
                        IBuffer result = await _socket.InputStream.ReadAsync(_buf.AsBuffer(), (uint)_buf.Length, Windows.Storage.Streams.InputStreamOptions.Partial);
                        if(result.Length > 0) {
                            //await _handler.OnData(_buf, 0, (int)result.Length);
                            _handler.OnData(_buf, 0, (int)result.Length);
                        }
                        else if (result.Length < 0) {
                            //await _handler.OnData(_buf, 0, (int)result.Length*-1);
                            _handler.OnData(_buf, 0, (int)result.Length * -1);
                        }
                        else {
					        _handler.OnClosed();
                            return;
                        }
                    }
                    catch(Exception ex) {
                        if(!_closed)
					        _handler.OnError(ex, ex.Message);
				        else
					        _handler.OnClosed();
                        return;
                    }
                }
                
            });
        }

        public bool DataAvailable
        {
			get {
                return true;
			}
		}

	}

	internal class ChannelSocket : AbstractSocket, ISSHChannelEventReceiver {
		private SSHChannel _channel;
		private bool _ready;


        protected IByteArrayHandler _handler;
		internal ChannelSocket(IByteArrayHandler h) {
            _handler = h;
			_ready = false;
		}
		internal SSHChannel SSHChennal {
			get {
				return _channel;
			}
			set {
				_channel = value;
			}
		}
        public void SetHandler(IByteArrayHandler h)
        {
            _handler = h;
        }
		public void Write([ReadOnlyArray()] byte[] data, int offset, int length) {
			if(!_ready || _channel==null) throw new Exception("channel not ready");
			_channel.Transmit(data, offset, length);
		}
        public void WriteByte(byte data)
        {
			if(!_ready || _channel==null) throw new Exception("channel not ready");
			byte[] t = new byte[1];
			t[0] = data;
			_channel.Transmit(t);
		}
        public bool DataAvailable
        {
			get {
				return _channel.Connection().Available();
			}
		}


		public void Flush() {
		}
        public void Close()
        {
			if(!_ready || _channel==null) throw new Exception("channel not ready");
			_channel.Close();
			if(_channel.Connection().ChannelCount()<=1) //close last channel
				_channel.Connection().Close();
		}

		public void OnData(byte[] data, int offset, int length)
        //public IAsyncAction OnData(byte[] data, int offset, int length)
        {
           //return Task.Run(async () => { await _handler.OnData(data, offset, length); }).AsAsyncAction();
            _handler.OnData(data, offset, length);
		}

		public void OnChannelEOF() {
			_handler.OnClosed();
		}

		public void OnChannelError(Exception error, string msg) {
			_handler.OnError(error, msg);
		}

		public void OnChannelClosed() {
			_handler.OnClosed();
		}

		public void OnChannelReady() {
			_ready = true;
		}

		public void OnExtendedData(int type, byte[] data) {
			//!!handle data
		}
		public void OnMiscPacket(byte type, byte[] data, int offset, int length) {
		}
	}
}
