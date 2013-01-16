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
using System.Text;

using GranadosRT.Routrek.PKI;
using GranadosRT.Routrek.Toolkit;

namespace GranadosRT.Routrek.SSHC {
	/// <summary>
	/// ConnectionInfo describes the attributes of the host or the connection.
	/// It is available after the connection is established without any errors.
	/// </summary>
	public interface SSHConnectionInfo {
		

		string ServerVersionString();
		string ClientVerisonString();
		string SupportedCipherAlgorithms();
		CipherAlgorithm AlgorithmForTransmittion();
		CipherAlgorithm AlgorithmForReception();

		string DumpHostKeyInKnownHostsStyle();

	
	}
}

namespace GranadosRT.Routrek.SSHCV1 {
	using GranadosRT.Routrek.SSHC;
    
	public sealed class SSH1ConnectionInfo : SSHConnectionInfo {
		internal SSHServerInfo _serverinfo;
        internal string _serverVersionString;
	    internal string _clientVersionString;
	    internal string _supportedCipherAlgorithms;
	    internal PublicKey _hostkey;

	    internal CipherAlgorithm _algorithmForTransmittion;
	    internal CipherAlgorithm _algorithmForReception;

		public string DumpHostKeyInKnownHostsStyle() {
			StringBuilder bld = new StringBuilder();
			bld.Append("ssh1 ");
			SSH1DataWriter wr = new SSH1DataWriter();
			//RSA only for SSH1
			RSAPublicKey rsa = (RSAPublicKey)_hostkey;
			wr.Write(rsa.Exponent);
			wr.Write(rsa.Modulus);
            byte[] tmpdata = Base64.Encode(wr.ToByteArray());
			bld.Append(Encoding.UTF8.GetString(tmpdata, 0 , tmpdata.Length));
			return bld.ToString();
		}

		public void SetSupportedCipherAlgorithms(int mask) {
			StringBuilder bld = new StringBuilder();
			if((mask &  2)!=0) AppendSupportedCipher(bld, "Idea");
			if((mask &  4)!=0) AppendSupportedCipher(bld, "DES");
			if((mask &  8)!=0) AppendSupportedCipher(bld, "TripleDES");
			if((mask & 16)!=0) AppendSupportedCipher(bld, "TSS");
			if((mask & 32)!=0) AppendSupportedCipher(bld, "RC4");
			if((mask & 64)!=0) AppendSupportedCipher(bld, "Blowfish");

			_supportedCipherAlgorithms = bld.ToString();
		}

		private static void AppendSupportedCipher(StringBuilder bld, string text) {
			if(bld.Length>0) bld.Append(',');
			bld.Append(text);
		}



        public string ServerVersionString() {
			return _serverVersionString;
		}
		public string ClientVerisonString() {
			return _clientVersionString;
		}
		public string SupportedCipherAlgorithms() {
			return _supportedCipherAlgorithms;
		}
		public CipherAlgorithm AlgorithmForTransmittion() {
			return _algorithmForTransmittion;
		}
		public CipherAlgorithm AlgorithmForReception() {
			return _algorithmForReception;
		}
		internal PublicKey HostKey() {
			return _hostkey;
		}

	}
}

namespace GranadosRT.Routrek.SSHCV2 {
	using GranadosRT.Routrek.SSHC;
	using GranadosRT.Routrek.PKI;

    public sealed class SSH2ConnectionInfo : SSHConnectionInfo
    {
		internal string _supportedHostKeyAlgorithms;
		internal PublicKeyAlgorithm _algorithmForHostKeyVerification;
		internal string _supportedKEXAlgorithms;
        internal string _serverVersionString;
	    internal string _clientVersionString;
	    internal string _supportedCipherAlgorithms;
	    internal PublicKey _hostkey;

	    internal CipherAlgorithm _algorithmForTransmittion;
	    internal CipherAlgorithm _algorithmForReception;

		public string SupportedHostKeyAlgorithms {
			get {
				return _supportedHostKeyAlgorithms;
			}
		}

		public PublicKeyAlgorithm AlgorithmForHostKeyVerification {
			get {
				return _algorithmForHostKeyVerification;
			}
		}
		public string SupportedKEXAlgorithms {
			get {
				return _supportedKEXAlgorithms;
			}
		}
		public string DumpHostKeyInKnownHostsStyle() {
			StringBuilder bld = new StringBuilder();
			bld.Append(SSH2Util.PublicKeyAlgorithmName(_hostkey.Algorithm));
			bld.Append(' ');
			SSH2DataWriter wr = new SSH2DataWriter();
			wr.Write(SSH2Util.PublicKeyAlgorithmName(_hostkey.Algorithm));
			if(_hostkey.Algorithm==PublicKeyAlgorithm.RSA) {
				RSAPublicKey rsa = (RSAPublicKey)_hostkey;
				wr.Write(rsa.Exponent);
				wr.Write(rsa.Modulus);
			}
			else if(_hostkey.Algorithm==PublicKeyAlgorithm.DSA) {
				DSAPublicKey dsa = (DSAPublicKey)_hostkey;
				wr.Write(dsa.P);
				wr.Write(dsa.Q);
				wr.Write(dsa.G);
				wr.Write(dsa.Y);
			}
			else
				//throw new Exception("Host key algorithm is unsupported");
                throw new Exception("Host key algorithm is unsupported");

            byte[] tmpdata = Base64.Encode(wr.ToByteArray());
			bld.Append(Encoding.UTF8.GetString(tmpdata, 0 ,tmpdata.Length));
			return bld.ToString();
		}

        public string ServerVersionString()
        {
            return _serverVersionString;
        }
        public string ClientVerisonString()
        {
            return _clientVersionString;
        }
        public string SupportedCipherAlgorithms()
        {
            return _supportedCipherAlgorithms;
        }
        public CipherAlgorithm AlgorithmForTransmittion()
        {
            return _algorithmForTransmittion;
        }
        public CipherAlgorithm AlgorithmForReception()
        {
            return _algorithmForReception;
        }
        internal PublicKey HostKey()
        {
            return _hostkey;
        }
	}
}

