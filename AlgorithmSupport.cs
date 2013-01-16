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
using Windows.Security.Cryptography.Core;
using GranadosRT.Routrek.Crypto;
using System.Runtime.InteropServices.WindowsRuntime;

namespace GranadosRT.Routrek.SSHC
{
	/*
	 * Cipher
	 *  The numbers at the tail of the class names indicates the version of SSH protocol.
	 *  The difference between V1 and V2 is the CBC procedure
	 */
	internal interface Cipher {
		void Encrypt(byte[] data, int offset, int len, byte[] result, int result_offset);
		void Decrypt(byte[] data, int offset, int len, byte[] result, int result_offset);
		int BlockSize { get; }
	}

	internal class BlowfishCipher1 : Cipher {
		private Blowfish _bf;
	
		public BlowfishCipher1(byte[] key) {
			_bf = new Blowfish();
			_bf.initializeKey(key);
		}
		public void Encrypt(byte[] data, int offset, int len, byte[] result, int ro) {
			_bf.encryptSSH1Style(data, offset, len, result, ro);
		}
		public void Decrypt(byte[] data, int offset, int len, byte[] result, int ro) {
			_bf.decryptSSH1Style(data, offset, len, result, ro);
		}
		public int BlockSize { get { return 8; } } 
	}
	internal class BlowfishCipher2 : Cipher {
		private Blowfish _bf;
	
		public BlowfishCipher2(byte[] key) {
			_bf = new Blowfish();
			_bf.initializeKey(key);
		}
		public BlowfishCipher2(byte[] key, byte[] iv) {
			_bf = new Blowfish();
			_bf.SetIV(iv);
			_bf.initializeKey(key);
		}
		public void Encrypt(byte[] data, int offset, int len, byte[] result, int ro) {
			_bf.encryptCBC(data, offset, len, result, ro);
		}
		public void Decrypt(byte[] data, int offset, int len, byte[] result, int ro) {
			_bf.decryptCBC(data, offset, len, result, ro);
		}
		public int BlockSize { get { return 8; } }
	}

	internal class TripleDESCipher1 : Cipher {
		private DES _DESCipher1;
		private DES _DESCipher2;
		private DES _DESCipher3;
	
		public TripleDESCipher1(byte[] key) {
			_DESCipher1 = new DES();
			_DESCipher2 = new DES();
			_DESCipher3 = new DES();
			
			_DESCipher1.InitializeKey(key, 0);
			_DESCipher2.InitializeKey(key, 8);
			_DESCipher3.InitializeKey(key,16);
		}
		public void Encrypt(byte[] data, int offset, int len, byte[] result, int ro) {
			byte[] buf1 = new byte[len];
			_DESCipher1.EncryptCBC(data, offset, len, result, ro);
			_DESCipher2.DecryptCBC(result, ro, buf1.Length, buf1, 0);
			_DESCipher3.EncryptCBC(buf1, 0, buf1.Length, result, ro);
		}
		public void Decrypt(byte[] data, int offset, int len, byte[] result, int ro) {
			byte[] buf1 = new byte[len];
			_DESCipher3.DecryptCBC(data, offset, len, result, ro);
			_DESCipher2.EncryptCBC(result, ro, buf1.Length, buf1, 0);
			_DESCipher1.DecryptCBC(buf1, 0, buf1.Length, result, ro);
		}
		public int BlockSize { get { return 8; } } 
	}
	internal class TripleDESCipher2 : Cipher {
		private DES _DESCipher1;
		private DES _DESCipher2;
		private DES _DESCipher3;
	
		public TripleDESCipher2(byte[] key) {
			_DESCipher1 = new DES();
			_DESCipher2 = new DES();
			_DESCipher3 = new DES();
			
			_DESCipher1.InitializeKey(key, 0);
			_DESCipher2.InitializeKey(key, 8);
			_DESCipher3.InitializeKey(key,16);
		}
		public TripleDESCipher2(byte[] key, byte[] iv) {
			_DESCipher1 = new DES();
			_DESCipher1.SetIV(iv);
			_DESCipher2 = new DES();
			_DESCipher2.SetIV(iv);
			_DESCipher3 = new DES();
			_DESCipher3.SetIV(iv);
			
			_DESCipher1.InitializeKey(key, 0);
			_DESCipher2.InitializeKey(key, 8);
			_DESCipher3.InitializeKey(key,16);
		}
		public void Encrypt(byte[] data, int offset, int len, byte[] result, int ro) {
			byte[] buf1 = new byte[8];
			int n = 0;
			while(n < len) {
				_DESCipher1.EncryptCBC(data, offset+n, 8, result, ro+n);
				_DESCipher2.DecryptCBC(result, ro+n, 8, buf1, 0);
				_DESCipher3.EncryptCBC(buf1, 0, 8, result, ro+n);
				_DESCipher1.SetIV(result, ro+n);
				_DESCipher2.SetIV(result, ro+n);
				_DESCipher3.SetIV(result, ro+n);
				n += 8;
			}
		}
		public void Decrypt(byte[] data, int offset, int len, byte[] result, int ro) {
			byte[] buf1 = new byte[8];
			int n = 0;
			while(n < len) {
				_DESCipher3.DecryptCBC(data, offset+n, 8, result, ro+n);
				_DESCipher2.EncryptCBC(result, ro+n, 8, buf1, 0);
				_DESCipher1.DecryptCBC(buf1, 0, 8, result, ro+n);
				_DESCipher3.SetIV(data, offset+n);
				_DESCipher2.SetIV(data, offset+n);
				_DESCipher1.SetIV(data, offset+n);
				n += 8;
			}
		}
		public int BlockSize { get { return 8; } } 
	}
	internal class RijindaelCipher2 : Cipher {

		private Rijndael _rijindael;
        private bool isCTR;

        public RijindaelCipher2(byte[] key, byte[] iv, CipherAlgorithm algorithm)
        {
			_rijindael = new Rijndael();
			_rijindael.SetIV(iv);
			_rijindael.InitializeKey(key);
            if (algorithm == CipherAlgorithm.AES256CTR ||
                                algorithm == CipherAlgorithm.AES192CTR ||
                                algorithm == CipherAlgorithm.AES128CTR)
                isCTR = true;
            else
                isCTR = false;
		}
		public void Encrypt(byte[] data, int offset, int len, byte[] result, int ro) {
            if (isCTR)
                _rijindael.encryptCTR(data, offset, len, result, ro);
            else
                _rijindael.encryptCBC(data, offset, len, result, ro);
		}
		public void Decrypt(byte[] data, int offset, int len, byte[] result, int ro) {
            if (isCTR)
                _rijindael.decryptCTR(data, offset, len, result, ro);
            else
                _rijindael.decryptCBC(data, offset, len, result, ro);
		}
		public int BlockSize { get { return _rijindael.GetBlockSize(); } }
	}

	/// <summary>
	/// Creates a cipher from given parameters
	/// </summary>
	internal class CipherFactory {
		public static Cipher CreateCipher(SSHProtocol protocol, CipherAlgorithm algorithm, byte[] key) {
			if(protocol==SSHProtocol.SSH1) {
				switch(algorithm) {
					case CipherAlgorithm.TripleDES:
						return new TripleDESCipher1(key);
					case CipherAlgorithm.Blowfish:
						return new BlowfishCipher1(key);
					default:
                        //throw new Exception("unknown algorithm " + algorithm);
                        throw new Exception("unknown algorithm " + algorithm);
				}
			}
			else {
				switch(algorithm) {
					case CipherAlgorithm.TripleDES:
						return new TripleDESCipher2(key);
					case CipherAlgorithm.Blowfish:
						return new BlowfishCipher2(key);
					default:
						//throw new Exception("unknown algorithm " + algorithm);
                        throw new Exception("unknown algorithm " + algorithm);
				}
			}
		}
		public static Cipher CreateCipher(SSHProtocol protocol, CipherAlgorithm algorithm, byte[] key, byte[] iv) {
			if(protocol==SSHProtocol.SSH1) {
				return CreateCipher(protocol, algorithm, key);
			}
			else {
				switch(algorithm) {
                    case CipherAlgorithm.TripleDES:
                        return new TripleDESCipher2(key, iv);
                    case CipherAlgorithm.Blowfish:
                        return new BlowfishCipher2(key, iv);
                    case CipherAlgorithm.AES128:
                    case CipherAlgorithm.AES192:
                    case CipherAlgorithm.AES256:
                    case CipherAlgorithm.AES128CTR:
                    case CipherAlgorithm.AES192CTR:
                    case CipherAlgorithm.AES256CTR:
                        return new RijindaelCipher2(key, iv, algorithm);
                    default:
                        throw new Exception("unknown algorithm " + algorithm);
				}
			}
		}

		/// <summary>
		/// returns necessary key size from Algorithm in bytes
		/// </summary>
		public static int GetKeySize(CipherAlgorithm algorithm) {
			switch(algorithm) {
                case CipherAlgorithm.TripleDES:
                    return 24;
                case CipherAlgorithm.Blowfish:
                case CipherAlgorithm.AES128:
                case CipherAlgorithm.AES128CTR:
                    return 16;
                case CipherAlgorithm.AES192:
                case CipherAlgorithm.AES192CTR:
                    return 24;
                case CipherAlgorithm.AES256:
                case CipherAlgorithm.AES256CTR:
                    return 32;
				default:
                    //throw new Exception("unknown algorithm " + algorithm);
                    throw new Exception("unknown algorithm " + algorithm);
			}
		}
		/// <summary>
		/// returns the block size from Algorithm in bytes
		/// </summary>
		public static int GetBlockSize(CipherAlgorithm algorithm) {
			switch(algorithm) {
                case CipherAlgorithm.TripleDES:
                case CipherAlgorithm.Blowfish:
                    return 8;
                case CipherAlgorithm.AES128:
                case CipherAlgorithm.AES192:
                case CipherAlgorithm.AES256:
                case CipherAlgorithm.AES128CTR:
                case CipherAlgorithm.AES192CTR:
                case CipherAlgorithm.AES256CTR:
                    return 16;
				default:
                    //throw new Exception("unknown algorithm " + algorithm);
                    throw new Exception("unknown algorithm " + algorithm);
			}
		}
		public static string AlgorithmToSSH2Name(CipherAlgorithm algorithm) {
			switch(algorithm) {
                case CipherAlgorithm.TripleDES:
                    return "3des-cbc";
                case CipherAlgorithm.Blowfish:
                    return "blowfish-cbc";
                case CipherAlgorithm.AES128:
                    return "aes128-cbc";
                case CipherAlgorithm.AES192:
                    return "aes192-cbc";
                case CipherAlgorithm.AES256:
                    return "aes256-cbc";
                case CipherAlgorithm.AES128CTR:
                    return "aes128-ctr";
                case CipherAlgorithm.AES192CTR:
                    return "aes192-ctr";
                case CipherAlgorithm.AES256CTR:
                    return "aes256-ctr";
				default:
                    //throw new Exception("unknown algorithm " + algorithm);
                    throw new Exception("unknown algorithm " + algorithm);
			}
		}
		public static CipherAlgorithm SSH2NameToAlgorithm(string name) {
            switch (name)
            {
                case "3des-cbc":
                    return CipherAlgorithm.TripleDES;
                case "blowfish-cbc":
                    return CipherAlgorithm.Blowfish;
                case "aes128-cbc":
                    return CipherAlgorithm.AES128;
                case "aes192-cbc":
                    return CipherAlgorithm.AES192;
                case "aes256-cbc":
                    return CipherAlgorithm.AES256;
                case "aes128-ctr":
                    return CipherAlgorithm.AES128CTR;
                case "aes192-ctr":
                    return CipherAlgorithm.AES192CTR;
                case "aes256-ctr":
                    return CipherAlgorithm.AES256CTR;
                default:
                    throw new Exception("Unknown algorithm " + name);
            }
		}
	}

 

	/**********        MAC        ***********/

	interface MAC {
		byte[] Calc(byte[] data);
		int Size { get; }
	}
	internal class MACSHA1 : MAC {
        private MacAlgorithmProvider _algorithm = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha1);
        private CryptographicKey key;
		public MACSHA1(byte[] key) {
            this.key = _algorithm.CreateKey(key.AsBuffer());
			//_algorithm = new HMACSHA1(key);
		}

		public byte[] Calc(byte[] data) {
			//_algorithm.Initialize();
			return CryptographicEngine.Sign(key,data.AsBuffer()).ToArray();
		}

		public int Size { get { return 20; } }
	}
	internal class MACFactory {
		public static MAC CreateMAC(MACAlgorithm algorithm, byte[] key) {
			if(algorithm==MACAlgorithm.HMACSHA1)
				return new MACSHA1(key);
			else
                //throw new Exception("unknown algorithm " + algorithm);
                throw new Exception("unknown algorithm " + algorithm);
		}
		public static int GetSize(MACAlgorithm algorithm) {
			if(algorithm==MACAlgorithm.HMACSHA1)
				return 20;
			else
                //throw new Exception("unknown algorithm " + algorithm);
                throw new Exception("unknown algorithm " + algorithm);
		}
	}
}
