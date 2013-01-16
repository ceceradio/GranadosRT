/* ---------------------------------------------------------------------------
 *
 * Copyright (c) Routrek Networks, Inc.    All Rights Reserved..
 * 
 * This file is a part of the Granados SSH Client Library that is subject to
 * the license included in the distributed package.
 * You may not use this file except in compliance with the license.
 * 
 * ---------------------------------------------------------------------------
 */
using System;
using System.IO;
//using System.Security.Cryptography;
//using System.Net.Sockets;
using Windows.Networking.Sockets;
using Windows.Networking;
using Windows.Security.Cryptography.Core;
using Windows.Security.Cryptography;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Diagnostics;
using System.Collections;
using System.Collections.Generic;
using GranadosRT.Routrek.PKI;
using GranadosRT.Routrek.SSHC;
using GranadosRT.Routrek.Toolkit;
using System.Threading.Tasks;
using Windows.Foundation;

namespace GranadosRT.Routrek.SSHCV1
{
	public sealed class SSH1Connection : SSHConnection {
        internal AbstractSocket _stream;
        internal ISSHConnectionEventReceiver _eventReceiver;

        protected byte[] _sessionID;
        internal Cipher _tCipher; //transmission
        //internal Cipher _rCipher; //reception
        internal SSHConnectionParameter _param;

        internal object _tLockObject = new Object();

        internal bool _closed;

        internal bool _autoDisconnect;

        internal AuthenticationResult _authenticationResult;

		private const int AUTH_NOT_REQUIRED = 0;
		private const int AUTH_REQUIRED = 1;

		private SSH1ConnectionInfo _cInfo;
		private int _shellID;

		private SSH1PacketBuilder _packetBuilder;
		private bool _executingShell;
		

		public SSH1Connection(SSHConnectionParameter param, ISSHConnectionEventReceiver er, string serverversion, string clientversion)  {
            _param = (SSHConnectionParameter)param.Clone();
            _eventReceiver = er;
            _channel_entries = new List<object>(16);
            _autoDisconnect = true;
			_cInfo = new SSH1ConnectionInfo();
			_cInfo._serverVersionString = serverversion;
			_cInfo._clientVersionString = clientversion;
			_shellID = -1;
			_packetBuilder = new SSH1PacketBuilder(new SynchronizedSSH1PacketHandler());
		}
        public bool IsClosed()
        {
            return _closed;
        }
        public bool Available()
        {
            if (_closed)
                return false;
            else
                return _stream.DataAvailable;
        }
        public bool AutoDisconnect()
        {
            return _autoDisconnect;
        }
        public SSHConnectionParameter Param()
        {
            return _param;
        }
        public AuthenticationResult AuthenticationResult()
        {
            return _authenticationResult;
        }

		public SSHConnectionInfo ConnectionInfo() {
			return _cInfo;
		}
		public IByteArrayHandler PacketBuilder() {
			return _packetBuilder;
		}
        public ISSHConnectionEventReceiver EventReceiver()
        {
            return _eventReceiver;
        }

        public AuthenticationResult DoConnect(AbstractSocket target)
        {
            _stream = target;
			
			// Phase2 receives server keys
			ReceiveServerKeys();
			if(_param.KeyCheck!=null && !_param.KeyCheck(_cInfo)) {
				_stream.Close();
                return GranadosRT.Routrek.SSHC.AuthenticationResult.Failure;
			}

			// Phase3 generates session key
			byte[] session_key = GenerateSessionKey();
			
			// Phase4 establishes the session key
			try {
				_packetBuilder.SetSignal(false);
				SendSessionKey(session_key);
				InitCipher(session_key);
			}
			finally {
				_packetBuilder.SetSignal(true);
			}
			ReceiveKeyConfirmation();
			
			// Phase5 user authentication
			SendUserName(_param.UserName);
			if(ReceiveAuthenticationRequirement()==AUTH_REQUIRED) {
				if(_param.AuthenticationType==AuthenticationType.Password) {
					SendPlainPassword();
				} else if(_param.AuthenticationType==AuthenticationType.PublicKey) {
					DoRSAChallengeResponse();
				}
				bool auth = ReceiveAuthenticationResult();
				if(!auth) throw new Exception(Strings.GetString("AuthenticationFailed"));

			}
			
			_packetBuilder.Handler = new CallbackSSH1PacketHandler(this);
            return GranadosRT.Routrek.SSHC.AuthenticationResult.Success;
		}

		internal void Transmit(SSH1Packet p) {
			lock(this) {
				p.WriteTo(_stream, _tCipher);
			}
		}

		public void Disconnect(string msg) {
			if(_closed) return;
			SSH1DataWriter w = new SSH1DataWriter();
			w.Write(msg);
			SSH1Packet p = SSH1Packet.FromPlainPayload(PacketType.SSH_MSG_DISCONNECT, w.ToByteArray());
			p.WriteTo(_stream, _tCipher);
			_stream.Flush();
			_closed = true;
			_stream.Close();
		}

		public void Close() {
			if(_closed) return;
			_closed = true;
			_stream.Close();
		} 

		public void SendIgnorableData(string msg) {
			SSH1DataWriter w = new SSH1DataWriter();
			w.Write(msg);
			SSH1Packet p = SSH1Packet.FromPlainPayload(PacketType.SSH_MSG_IGNORE, w.ToByteArray());
			Transmit(p);
		}

	
		private void ReceiveServerKeys() {
			SSH1Packet SSH1Packet = ReceivePacket();
			if(SSH1Packet.Type!=PacketType.SSH_SMSG_PUBLIC_KEY) throw new Exception("unexpected SSH SSH1Packet type " + SSH1Packet.Type);
			
			SSH1DataReader reader = new SSH1DataReader(SSH1Packet.Data);
			_cInfo._serverinfo = new SSHServerInfo(reader); 
			_cInfo._hostkey = new RSAPublicKey(_cInfo._serverinfo.host_key_public_exponent, _cInfo._serverinfo.host_key_public_modulus);
			
			//read protocol support parameters
			int protocol_flags = reader.ReadInt32();
			int supported_ciphers_mask = reader.ReadInt32();
			_cInfo.SetSupportedCipherAlgorithms(supported_ciphers_mask);
			int supported_authentications_mask = reader.ReadInt32();
			//Debug.WriteLine(String.Format("ServerOptions {0} {1} {2}", protocol_flags, supported_ciphers_mask, supported_authentications_mask));

			if(reader.Rest>0) throw new Exception("data length mismatch");
			
			//Debug Info
			/*
			System.out.println("Flags="+protocol_flags);
			System.out.println("Cipher="+supported_ciphers_mask);
			System.out.println("Auth="+supported_authentications_mask);
			*/
			
			bool found = false;
			foreach(CipherAlgorithm a in _param.PreferableCipherAlgorithms) {
				if(a!=CipherAlgorithm.Blowfish && a!=CipherAlgorithm.TripleDES)
					continue;
				else if(a==CipherAlgorithm.Blowfish && (supported_ciphers_mask & (1 << (int)CipherAlgorithm.Blowfish))==0)
					continue; 
				else if(a==CipherAlgorithm.TripleDES && (supported_ciphers_mask & (1 << (int)CipherAlgorithm.TripleDES))==0)
					continue; 

				_cInfo._algorithmForReception = _cInfo._algorithmForTransmittion = a;  
				found = true;
				break;
			}

			if(!found) 
				throw new Exception(String.Format(Strings.GetString("ServerNotSupportedX"), "Blowfish/TripleDES"));

			if(_param.AuthenticationType==AuthenticationType.Password && (supported_authentications_mask & (1 << (int)AuthenticationType.Password))==0)
				throw new Exception(String.Format(Strings.GetString("ServerNotSupportedPassword")));
			if(_param.AuthenticationType==AuthenticationType.PublicKey && (supported_authentications_mask & (1 << (int)AuthenticationType.PublicKey))==0)
				throw new Exception(String.Format(Strings.GetString("ServerNotSupportedRSA")));
		}
	
		private byte[] GenerateSessionKey() {
			//session key(256bits)
			byte[] session_key = new byte[32];
			_param.Random.NextBytes(session_key); 
			//for(int i=0; i<32; i++) Debug.Write(String.Format("0x{0:x}, ", session_key[i]));
			
			return session_key;
		}
	
		private void SendSessionKey(byte[] session_key) {
			try
			{
				//step1 XOR with session_id
				byte[] working_data = new byte[session_key.Length];
				byte[] session_id = CalcSessionID();
				Array.Copy(session_key, 0, working_data, 0, session_key.Length);
				for(int i=0; i<session_id.Length; i++) working_data[i] ^= session_id[i];

				//step2 decrypts with RSA
				RSAPublicKey first_encryption;
				RSAPublicKey second_encryption;
				SSHServerInfo si = _cInfo._serverinfo;
				int first_key_bytelen, second_key_bytelen;
				if(si.server_key_bits < si.host_key_bits)
				{
					first_encryption  = new RSAPublicKey(si.server_key_public_exponent, si.server_key_public_modulus);
					second_encryption = new RSAPublicKey(si.host_key_public_exponent, si.host_key_public_modulus);
					first_key_bytelen = (si.server_key_bits+7)/8;
					second_key_bytelen = (si.host_key_bits+7)/8;
				}
				else
				{
					first_encryption  = new RSAPublicKey(si.host_key_public_exponent, si.host_key_public_modulus);
					second_encryption = new RSAPublicKey(si.server_key_public_exponent, si.server_key_public_modulus);
					first_key_bytelen = (si.host_key_bits+7)/8;
					second_key_bytelen = (si.server_key_bits+7)/8;
				}

				BigInteger first_result = RSAUtil.PKCS1PadType2(new BigInteger(working_data), first_key_bytelen, _param.Random).modPow(first_encryption.Exponent, first_encryption.Modulus);
				BigInteger second_result = RSAUtil.PKCS1PadType2(first_result, second_key_bytelen, _param.Random).modPow(second_encryption.Exponent, second_encryption.Modulus);

				//output
				SSH1DataWriter writer = new SSH1DataWriter();
				writer.Write((byte)_cInfo._algorithmForTransmittion);
				writer.Write(si.anti_spoofing_cookie);
				writer.Write(second_result);
				writer.Write(0); //protocol flags

				//send
				SSH1Packet SSH1Packet = SSH1Packet.FromPlainPayload(PacketType.SSH_CMSG_SESSION_KEY, writer.ToByteArray());
				SSH1Packet.WriteTo(_stream);

				_sessionID = session_id;

			}
			catch(Exception e)
			{
				if(e is IOException)
					throw (IOException)e;
				else
				{
					string t = e.StackTrace;
					throw new Exception(e.Message); //IOException以外はみなSSHExceptionにしてしまう
				}
			}
		}
	
		private void ReceiveKeyConfirmation() {
			SSH1Packet SSH1Packet = ReceivePacket();
			if(SSH1Packet.Type!=PacketType.SSH_SMSG_SUCCESS)
				throw new Exception("unexpected packet type [" + SSH1Packet.Type +"] at ReceiveKeyConfirmation()");
		}
	
		private int ReceiveAuthenticationRequirement() {
			SSH1Packet SSH1Packet = ReceivePacket();
			if(SSH1Packet.Type==PacketType.SSH_SMSG_SUCCESS)
				return AUTH_NOT_REQUIRED;
			else if(SSH1Packet.Type==PacketType.SSH_SMSG_FAILURE)
				return AUTH_REQUIRED;  
			else
				throw new Exception("type " + SSH1Packet.Type);
		}
	
		private void SendUserName(string username) {
			SSH1DataWriter writer = new SSH1DataWriter();
			writer.Write(username);
			SSH1Packet SSH1Packet = SSH1Packet.FromPlainPayload(PacketType.SSH_CMSG_USER, writer.ToByteArray());
			SSH1Packet.WriteTo(_stream, _tCipher);
		}
		private void SendPlainPassword() {
			SSH1DataWriter writer = new SSH1DataWriter();
			writer.Write(_param.Password);
			SSH1Packet SSH1Packet = SSH1Packet.FromPlainPayload(PacketType.SSH_CMSG_AUTH_PASSWORD, writer.ToByteArray());
			SSH1Packet.WriteTo(_stream, _tCipher);
		}

		//RSA authentication
		private void DoRSAChallengeResponse() {
			//read key
			SSH1UserAuthKey key = new SSH1UserAuthKey(_param.IdentityFile, _param.Password);
			SSH1DataWriter w = new SSH1DataWriter();
			w.Write(key.PublicModulus);
			SSH1Packet p = SSH1Packet.FromPlainPayload(PacketType.SSH_CMSG_AUTH_RSA, w.ToByteArray());
			p.WriteTo(_stream, _tCipher);

			p = ReceivePacket();
			if(p.Type==PacketType.SSH_SMSG_FAILURE)
				throw new Exception(Strings.GetString("ServerRefusedRSA"));
			else if(p.Type!=PacketType.SSH_SMSG_AUTH_RSA_CHALLENGE)
				throw new Exception(String.Format(Strings.GetString("UnexpectedResponse"), p.Type));

			//creating challenge
			SSH1DataReader r = new SSH1DataReader(p.Data);
			BigInteger challenge = key.decryptChallenge(r.ReadMPInt());
			byte[] rawchallenge = RSAUtil.StripPKCS1Pad(challenge, 2).getBytes();

			//building response
			MemoryStream bos = new MemoryStream();
			bos.Write(rawchallenge, 0, rawchallenge.Length); //!!mindtermでは頭が０かどうかで変なハンドリングがあった
			bos.Write(_sessionID, 0, _sessionID.Length);
            byte[] response = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5).HashData(bos.ToArray().AsBuffer()).ToArray(); ;

			w = new SSH1DataWriter();
			w.Write(response);
			p = SSH1Packet.FromPlainPayload(PacketType.SSH_CMSG_AUTH_RSA_RESPONSE, w.ToByteArray());
			p.WriteTo(_stream, _tCipher);

		}

		private bool ReceiveAuthenticationResult() {
			SSH1Packet SSH1Packet = ReceivePacket();
			PacketType type = SSH1Packet.Type;
			if(type==PacketType.SSH_MSG_DEBUG) {
				SSH1DataReader r = new SSH1DataReader(SSH1Packet.Data);
				//Debug.WriteLine("receivedd debug message:"+Encoding.ASCII.GetString(r.ReadString()));
				return ReceiveAuthenticationResult();
			}
			else if(type==PacketType.SSH_SMSG_SUCCESS)
				return true;
			else if(type==PacketType.SSH_SMSG_FAILURE)
				return false;
			else
				throw new Exception("type: " + type);
		}

		public SSHChannel OpenShell(ISSHChannelEventReceiver receiver) {
			if(_shellID!=-1)
				throw new Exception("A shell is opened already");
			_shellID = RegisterChannelEventReceiver(null, receiver)._localID;
			SendRequestPTY();
			_executingShell = true;
			return new SSH1Channel(this, ChannelType.Shell, _shellID);
		}

		private void SendRequestPTY() {
			SSH1DataWriter writer = new SSH1DataWriter();
			writer.Write(_param.TerminalName);
			writer.Write(_param.TerminalHeight);
			writer.Write(_param.TerminalWidth);
			writer.Write(_param.TerminalPixelWidth);
			writer.Write(_param.TerminalPixelHeight);
			writer.Write(new byte[1]); //TTY_OP_END
			SSH1Packet SSH1Packet = SSH1Packet.FromPlainPayload(PacketType.SSH_CMSG_REQUEST_PTY, writer.ToByteArray());
			SSH1Packet.WriteTo(_stream, _tCipher);
		}
	
		private void ExecShell() {
			//System.out.println("EXEC SHELL");
			SSH1Packet SSH1Packet = SSH1Packet.FromPlainPayload(PacketType.SSH_CMSG_EXEC_SHELL);
			SSH1Packet.WriteTo(_stream, _tCipher);
		}

		public SSHChannel ForwardPort(ISSHChannelEventReceiver receiver, string remote_host, int remote_port, string originator_host, int originator_port) {
			if(_shellID==-1) {
				ExecShell();
				_shellID = RegisterChannelEventReceiver(null, new SSH1DummyReceiver())._localID;
			}
 
			int local_id = this.RegisterChannelEventReceiver(null, receiver)._localID;

			SSH1DataWriter writer = new SSH1DataWriter();
			writer.Write(local_id); //channel id is fixed to 0
			writer.Write(remote_host);
			writer.Write(remote_port);
			//originator is specified only if SSH_PROTOFLAG_HOST_IN_FWD_OPEN is specified
			//writer.Write(originator_host);
			SSH1Packet SSH1Packet = SSH1Packet.FromPlainPayload(PacketType.SSH_MSG_PORT_OPEN, writer.ToByteArray());
			SSH1Packet.WriteTo(_stream, _tCipher);

			return new SSH1Channel(this, ChannelType.ForwardedLocalToRemote, local_id);
		}

		public void ListenForwardedPort(string allowed_host, int bind_port) {
			SSH1DataWriter writer = new SSH1DataWriter();
			writer.Write(bind_port);
			writer.Write(allowed_host);
			writer.Write(0);
			SSH1Packet p = SSH1Packet.FromPlainPayload(PacketType.SSH_CMSG_PORT_FORWARD_REQUEST, writer.ToByteArray());
			p.WriteTo(_stream, _tCipher);

			if(_shellID==-1) {
				ExecShell();
				_shellID = RegisterChannelEventReceiver(null, new SSH1DummyReceiver())._localID;
			}

		}
		public void CancelForwardedPort(string host, int port) {
			throw new NotSupportedException("not implemented");
		}

		private void ProcessPortforwardingRequest(ISSHConnectionEventReceiver receiver, SSH1Packet packet) {
			SSH1DataReader reader = new SSH1DataReader(packet.Data);
			int server_channel = reader.ReadInt32();
            byte[] tmpdata = reader.ReadString();
			string host = Encoding.UTF8.GetString(tmpdata,0, tmpdata.Length);
			int port = reader.ReadInt32();

			SSH1DataWriter writer = new SSH1DataWriter();
			PortForwardingCheckResult result = receiver.CheckPortForwardingRequest(host, port, "", 0);
			if(result.allowed) {
				int local_id = this.RegisterChannelEventReceiver(null, result.channel)._localID;
				_eventReceiver.EstablishPortforwarding(result.channel, new SSH1Channel(this, ChannelType.ForwardedRemoteToLocal, local_id, server_channel));

				writer.Write(server_channel);
				writer.Write(local_id);
				SSH1Packet p = SSH1Packet.FromPlainPayload(PacketType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION, writer.ToByteArray());
				p.WriteTo(_stream, _tCipher);
			}
			else {
				writer.Write(server_channel);
				SSH1Packet p = SSH1Packet.FromPlainPayload(PacketType.SSH_MSG_CHANNEL_OPEN_FAILURE, writer.ToByteArray());
				p.WriteTo(_stream, _tCipher);
			}
		}

		private byte[] CalcSessionID() {
			MemoryStream bos = new MemoryStream();
			SSHServerInfo si = _cInfo._serverinfo;
			byte[] h = si.host_key_public_modulus.getBytes(); 
			byte[] s = si.server_key_public_modulus.getBytes();
			//System.out.println("len h="+h.Length);
			//System.out.println("len s="+s.Length);
			
			int off_h = (h[0]==0? 1 : 0);
			int off_s = (s[0]==0? 1 : 0);
			bos.Write(h, off_h, h.Length-off_h);
			bos.Write(s, off_s, s.Length-off_s);
			bos.Write(si.anti_spoofing_cookie, 0, si.anti_spoofing_cookie.Length);
			
			byte[] session_id = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5).HashData(bos.ToArray().AsBuffer()).ToArray();
			//System.out.println("sess-id-len=" + session_id.Length);
			return session_id;
		}
	
		//init ciphers
		private void InitCipher(byte[] session_key) {
			_tCipher = CipherFactory.CreateCipher(SSHProtocol.SSH1, _cInfo._algorithmForTransmittion, session_key);
			Cipher rc = CipherFactory.CreateCipher(SSHProtocol.SSH1, _cInfo._algorithmForReception, session_key);
			_packetBuilder.SetCipher(rc, _param.CheckMACError);
		}

		private SSH1Packet ReceivePacket() {
			while(true) {
				SSH1Packet p = null;
				SynchronizedSSH1PacketHandler handler = (SynchronizedSSH1PacketHandler)_packetBuilder.Handler;
				if(!handler.HasPacket) {
					handler.Wait();
					if(handler.State==ReceiverState.Error)
						throw new Exception(handler.ErrorMessage);
					else if(handler.State==ReceiverState.Closed)
						throw new Exception("socket closed");
				}
				p = handler.PopPacket();

				SSH1DataReader r = new SSH1DataReader(p.Data);
				PacketType pt = p.Type;
				if(pt==PacketType.SSH_MSG_IGNORE) {
					if(_eventReceiver!=null) _eventReceiver.OnIgnoreMessage(r.ReadString());
				}
				else if(pt==PacketType.SSH_MSG_DEBUG) {
					if(_eventReceiver!=null) _eventReceiver.OnDebugMessage(false, r.ReadString());
				}
				else
					return p;
			}
		}
	
		//internal async Task AsyncReceivePacket(SSH1Packet p) {
        internal void AsyncReceivePacket(SSH1Packet p)
        {
			try {
				int len = 0, channel = 0;
				switch(p.Type) {
					case PacketType.SSH_SMSG_STDOUT_DATA:
						len = SSHUtil.ReadInt32(p.Data, 0);
						//await FindChannelEntry(_shellID)._receiver.OnData(p.Data, 4, len);
                        FindChannelEntry(_shellID)._receiver.OnData(p.Data, 4, len);
						break;
					case PacketType.SSH_SMSG_STDERR_DATA: {
						SSH1DataReader re = new SSH1DataReader(p.Data);
						FindChannelEntry(_shellID)._receiver.OnExtendedData((int)PacketType.SSH_SMSG_STDERR_DATA, re.ReadString());
					}
						break;
					case PacketType.SSH_MSG_CHANNEL_DATA:
						channel = SSHUtil.ReadInt32(p.Data, 0);
						len = SSHUtil.ReadInt32(p.Data, 4);
                        //await FindChannelEntry(channel)._receiver.OnData(p.Data, 8, len);
                        FindChannelEntry(channel)._receiver.OnData(p.Data, 8, len);
						break;
					case PacketType.SSH_MSG_PORT_OPEN:
						this.ProcessPortforwardingRequest(_eventReceiver, p);
						break;
					case PacketType.SSH_MSG_CHANNEL_CLOSE: {
						channel = SSHUtil.ReadInt32(p.Data, 0);
						ISSHChannelEventReceiver r = FindChannelEntry(channel)._receiver;
						UnregisterChannelEventReceiver(channel);
						r.OnChannelClosed();
					}
						break;
					case PacketType.SSH_MSG_CHANNEL_CLOSE_CONFIRMATION:
						channel = SSHUtil.ReadInt32(p.Data, 0);
						break;
					case PacketType.SSH_MSG_DISCONNECT:
						_eventReceiver.OnConnectionClosed();
						break;
					case PacketType.SSH_SMSG_EXITSTATUS:
						FindChannelEntry(_shellID)._receiver.OnChannelClosed();
						break;
					case PacketType.SSH_MSG_DEBUG: {
						SSH1DataReader re = new SSH1DataReader(p.Data);
						_eventReceiver.OnDebugMessage(false, re.ReadString());
					}
						break;
					case PacketType.SSH_MSG_IGNORE: {
						SSH1DataReader re = new SSH1DataReader(p.Data);
						_eventReceiver.OnIgnoreMessage(re.ReadString());
					}
						break;
					case PacketType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION: {
						int local = SSHUtil.ReadInt32(p.Data, 0);
						int remote = SSHUtil.ReadInt32(p.Data, 4);
						FindChannelEntry(local)._receiver.OnChannelReady();
					}
						break;
					case PacketType.SSH_SMSG_SUCCESS:
						if(_executingShell) {
							ExecShell();
							this.FindChannelEntry(_shellID)._receiver.OnChannelReady();
							_executingShell = false;
						}
						break;
					default:
						_eventReceiver.OnUnknownMessage((byte)p.Type, p.Data);
						break;
				}
			}
			catch(Exception ex) {
				if(!_closed)
					_eventReceiver.OnError(ex, ex.Message);
			}
		}
        /**
		 * opens another SSH connection via port-forwarded connection
		 */
        public SSHConnection OpenPortForwardedAnotherConnection(SSHConnectionParameter param, ISSHConnectionEventReceiver receiver, string host, int port)
        {
            ProtocolNegotiationHandler pnh = new ProtocolNegotiationHandler(param);
            ChannelSocket s = new ChannelSocket(pnh);

            SSHChannel ch = ForwardPort(s, host, port, "localhost", 0);
            s.SSHChennal = ch;
            return SSH1Connection.Connect(param, receiver, pnh, s);
        }

        //channel id support
        protected class ChannelEntry
        {
            public int _localID;
            public ISSHChannelEventReceiver _receiver;
            internal SSHChannel _channel;
        }

        protected List<object> _channel_entries;
        protected int _channel_sequence;
        protected ChannelEntry FindChannelEntry(int id)
        {
            for (int i = 0; i < _channel_entries.Count; i++)
            {
                ChannelEntry e = (ChannelEntry)_channel_entries[i];
                if (e._localID == id) return e;
            }
            return null;
        }
        protected ChannelEntry RegisterChannelEventReceiver(SSHChannel ch, ISSHChannelEventReceiver r)
        {
            lock (this)
            {
                ChannelEntry e = new ChannelEntry();
                e._channel = ch;
                e._receiver = r;
                e._localID = _channel_sequence++;

                for (int i = 0; i < _channel_entries.Count; i++)
                {
                    if (_channel_entries[i] == null)
                    {
                        _channel_entries[i] = e;
                        return e;
                    }
                }
                _channel_entries.Add(e);
                return e;
            }
        }
        public void RegisterChannel(int local_id, SSHChannel ch)
        {
            FindChannelEntry(local_id)._channel = ch;
        }
        public void UnregisterChannelEventReceiver(int id)
        {
            lock (this)
            {
                foreach (ChannelEntry e in _channel_entries)
                {
                    if (e._localID == id)
                    {
                        _channel_entries.Remove(e);
                        break;
                    }
                }
                if (this.ChannelCount() == 0 && _autoDisconnect) Disconnect(""); //auto close
            }
        }
        public int ChannelCount()
        {
            int r = 0;
            for (int i = 0; i < _channel_entries.Count; i++)
            {
                if (_channel_entries[i] != null) r++;
            }
            return r;
        }


        //establishes a SSH connection in subject to ConnectionParameter
        public static SSHConnection Connect(SSHConnectionParameter param, ISSHConnectionEventReceiver receiver, StreamSocket underlying_socket)
        {
            if (param.UserName == null) throw new InvalidOperationException("UserName property is not set");
            if (param.Password == null) throw new InvalidOperationException("Password property is not set");

            ProtocolNegotiationHandler pnh = new ProtocolNegotiationHandler(param);
            PlainSocket s = new PlainSocket(underlying_socket, pnh);
            s.RepeatAsyncRead();
            return ConnectMain(param, receiver, pnh, s);
        }
        public static SSHConnection Connect(SSHConnectionParameter param, ISSHConnectionEventReceiver receiver, ProtocolNegotiationHandler pnh, AbstractSocket s)
        {
            if (param.UserName == null) throw new InvalidOperationException("UserName property is not set");
            if (param.Password == null) throw new InvalidOperationException("Password property is not set");

            return ConnectMain(param, receiver, pnh, s);
        }
        private static SSHConnection ConnectMain(SSHConnectionParameter param, ISSHConnectionEventReceiver receiver, ProtocolNegotiationHandler pnh, AbstractSocket s)
        {
            pnh.Wait();

            if (pnh.State != ReceiverState.Ready) throw new Exception(pnh.ErrorMessage);

            string sv = pnh.ServerVersion;

            SSHConnection con = null;
            //if (param.Protocol == SSHProtocol.SSH1)
                con = new SSH1Connection(param, receiver, sv, SSHUtil.ClientVersionString(param.Protocol));
            //else
            //    con = new SSH2Connection(param, receiver, sv, SSHUtil.ClientVersionString(param.Protocol));

            s.SetHandler(con.PacketBuilder());
            SendMyVersion(s, param);

            if (con.DoConnect(s) != GranadosRT.Routrek.SSHC.AuthenticationResult.Failure)
                return con;
            else
            {
                s.Close();
                return null;
            }
        }

        private static void SendMyVersion(AbstractSocket stream, SSHConnectionParameter param)
        {
            string cv = SSHUtil.ClientVersionString(param.Protocol);
            if (param.Protocol == SSHProtocol.SSH1)
                cv += param.SSH1VersionEOL;
            else
                cv += "\r\n";
            byte[] data = Encoding.UTF8.GetBytes(cv);
            stream.Write(data, 0, data.Length);
        }
    }

	class SSH1Channel : SSHChannel {
        protected ChannelType _type;
        protected int _localID;
        protected int _remoteID;
        protected SSHConnection _connection;

		public SSH1Channel(SSHConnection con, ChannelType type, int local_id) {
            con.RegisterChannel(local_id, this);
            _connection = con;
            _type = type;
            _localID = local_id;
		}
		public SSH1Channel(SSHConnection con, ChannelType type, int local_id, int remote_id) {
            con.RegisterChannel(local_id, this);
            _connection = con;
            _type = type;
            _localID = local_id;
			_remoteID = remote_id;
		}

        public int LocalChannelID()
        {
            return _localID;
        }
        public int RemoteChannelID()
        {
            return _remoteID;
        }
        public SSHConnection Connection()
        {
            return _connection;
        }
        public ChannelType Type()
        {
            return _type;
        }

		/**
		 * resizes the size of terminal
		 */
		public void ResizeTerminal(int width, int height, int pixel_width, int pixel_height) {
			SSH1DataWriter writer = new SSH1DataWriter();
			writer.Write(height);
			writer.Write(width);
			writer.Write(pixel_width);
			writer.Write(pixel_height);
			SSH1Packet p = SSH1Packet.FromPlainPayload(PacketType.SSH_CMSG_WINDOW_SIZE, writer.ToByteArray());
			Transmit(p);
		}

		/**
		* transmits channel data 
		*/
		public void Transmit(byte[] data) {
			SSH1DataWriter wr = new SSH1DataWriter();
			if(_type==ChannelType.Shell) {
				wr.WriteAsString(data);
				SSH1Packet p = SSH1Packet.FromPlainPayload(PacketType.SSH_CMSG_STDIN_DATA, wr.ToByteArray());
				Transmit(p);
			}
			else {
				wr.Write(_remoteID);
				wr.WriteAsString(data);
				SSH1Packet p = SSH1Packet.FromPlainPayload(PacketType.SSH_MSG_CHANNEL_DATA, wr.ToByteArray());
				Transmit(p);
			}
		}
		/**
		* transmits channel data 
		*/
		public void Transmit(byte[] data, int offset, int length) {
			SSH1DataWriter wr = new SSH1DataWriter();
			if(_type==ChannelType.Shell) {
				wr.WriteAsString(data, offset, length);
				SSH1Packet p = SSH1Packet.FromPlainPayload(PacketType.SSH_CMSG_STDIN_DATA, wr.ToByteArray());
				Transmit(p);
			}
			else {
				wr.Write(_remoteID);
				wr.WriteAsString(data, offset, length);
				SSH1Packet p = SSH1Packet.FromPlainPayload(PacketType.SSH_MSG_CHANNEL_DATA, wr.ToByteArray());
				Transmit(p);
			}
		}

		public void SendEOF() {
		}


		/**
		 * closes this channel
		 */
        public void Close()
        {
			if(_connection.IsClosed()) return;

			if(_type==ChannelType.Shell) {
				SSH1DataWriter wr2 = new SSH1DataWriter();
				wr2.Write(_remoteID);
				SSH1Packet p2 = SSH1Packet.FromPlainPayload(PacketType.SSH_CMSG_EOF, wr2.ToByteArray());
				Transmit(p2);
			}

			SSH1DataWriter wr = new SSH1DataWriter();
			wr.Write(_remoteID);
			SSH1Packet p = SSH1Packet.FromPlainPayload(PacketType.SSH_MSG_CHANNEL_CLOSE, wr.ToByteArray());
			Transmit(p);
		}

		private void Transmit(SSH1Packet p) {
			((SSH1Connection)_connection).Transmit(p);
		}
	}

	//if port forwardings are performed without a shell, we use SSH1DummyChannel to receive shell data
	internal class SSH1DummyReceiver : ISSHChannelEventReceiver {
		//public IAsyncAction OnData(byte[] data, int offset, int length) {
        public void OnData(byte[] data, int offset, int length)
        {
            //return Task.Run(() => { }).AsAsyncAction();
		}
		public void OnExtendedData(int type, byte[] data) {
		}
		public void OnChannelClosed() {
		}
		public void OnChannelEOF() {
		}
		public void OnChannelReady() {
		}
		public void OnChannelError(Exception error, string msg) {
		}
		public void OnMiscPacket(byte packet_type, byte[] data, int offset, int length) {
		}
	}
}
