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
using System.Diagnostics;
using System.IO;
using Windows.Storage;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.ApplicationModel.Resources;
using System.Text;
using GranadosRT.Routrek.PKI;
using GranadosRT.Routrek.SSHC;
using GranadosRT.Routrek.Toolkit;
using System.Runtime.InteropServices.WindowsRuntime;

namespace GranadosRT.Routrek.SSHCV2
{

	internal sealed class SSH2UserAuthKey {

		private const int SSH_COM_MAGIC_VAL = 0x3f6ff9eb;
        private const int OPEN_SSH_MAGIC_VAL = 0x00003082;

        private const string PKCS8_DSA_HEADER = "-----BEGIN DSA PRIVATE KEY-----";
        private const string PKCS8_RSA_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
        private const string SSH_COM_HEADER = "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----";

		private KeyPair _keypair;

        private static ResourceLoader resLoader = new Windows.ApplicationModel.Resources.ResourceLoader();

		public SSH2UserAuthKey(KeyPair kp) {
			_keypair = kp;
		}

        internal PublicKeyAlgorithm Algorithm
        {
			get {
				return _keypair.Algorithm;
			}
		}
		internal KeyPair KeyPair {
			get {
				return _keypair;
			}
		}

		public byte[] Sign([ReadOnlyArray()]byte[] data) {
			PublicKeyAlgorithm a = _keypair.Algorithm;
			if(a==PublicKeyAlgorithm.RSA)
				return ((RSAKeyPair)_keypair).SignWithSHA1(data);
			else
				return ((DSAKeyPair)_keypair).Sign(HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha1).HashData(data.AsBuffer()).ToArray());
		}
		public byte[] GetPublicKeyBlob() {
			SSH2DataWriter w = new SSH2DataWriter();
			w.Write(SSH2Util.PublicKeyAlgorithmName(_keypair.Algorithm));
			_keypair.PublicKey.WriteTo(w);
			return w.ToByteArray();
		}
		

		public static byte[] PassphraseToKey(string passphrase, int length) {
			HashAlgorithmProvider md5 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5);
			byte[] pp = Encoding.UTF8.GetBytes(passphrase);
			int hashlen = (int)md5.HashLength/8;
            
			byte[] buf = new byte[((length + hashlen) / hashlen) * hashlen];
			int offset = 0;
			
			while(offset < length) {
				MemoryStream s = new MemoryStream();
				s.Write(pp, 0, pp.Length);
				if(offset > 0) s.Write(buf, 0, offset);
				Array.Copy(md5.HashData(s.ToArray().AsBuffer()).ToArray(), 0, buf, offset, hashlen);
				offset += hashlen;
                md5 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5);
			}

			byte[] key = new byte[length];
			Array.Copy(buf, 0, key, 0, length);
			return key;
		}
        public static SSH2UserAuthKey FromPrivateKeyFile(string filename, string passphrase)
        {
            var fileToLaunch = StorageFile.GetFileFromPathAsync(filename);
            fileToLaunch.AsTask().Wait();
            var streamToLaunch = fileToLaunch.AsTask().Result.OpenStreamForReadAsync();
            streamToLaunch.Wait();
            return FromStream(streamToLaunch.Result, passphrase);
        }
        private static SSH2UserAuthKey FromStream(Stream strm, string passphrase)
        {
            StreamReader r = new StreamReader(strm, Encoding.UTF8);
            string l = r.ReadLine();
            if (l == null) {
                throw new Exception(resLoader.GetString("BrokenKeyFile"));
            }
            else if (l == PKCS8_DSA_HEADER) 
            {
                return FromDSAOpenSSHStyleStream(r, passphrase);
            }
            else if (l == PKCS8_RSA_HEADER)
            {
                return FromRSAOpenSSHStyleStream(r, passphrase);
            }
            else if (l == SSH_COM_HEADER)
            {
                return FromSECSHStyleStream(r, passphrase);
            }
            else
            {
                throw new Exception(resLoader.GetString("BrokenKeyFile"));
            }
        }

        private static int GetIntegerSize(SSH2DataReader binr)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)		//expect integer
                return 0;
            bt = binr.ReadByte();

            if (bt == 0x81)
                count = binr.ReadByte();	// data size in next byte
            else
                if (bt == 0x82)
                {
                    highbyte = binr.ReadByte();	// data size in next 2 bytes
                    lowbyte = binr.ReadByte();
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                    count = BitConverter.ToInt32(modint, 0);
                }
                else
                {
                    count = bt;		// we already have the data size
                }



            while (binr.ReadByte() == 0x00)
            {	//remove high order zeros in data
                count -= 1;
            }
            binr.Seek(-1);		//last ReadByte wasn't a removed zero, so back up a byte
            return count;
        }

        /*
		 * Format style note
		 *  ---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
		 *  Comment: *******
		 *  <base64-encoded body>
		 *  ---- END SSH2 ENCRYPTED PRIVATE KEY ----
		 * 
		 *  body = MAGIC_VAL || body-length || type(string) || encryption-algorithm-name(string) || encrypted-body(string)
		 *  encrypted-body = array of BigInteger(algorithm-specific)
		 */
        internal static SSH2UserAuthKey FromDSAOpenSSHStyleStream(StreamReader r, string passphrase)
        {
            string l = r.ReadLine();
            StringBuilder buf = new StringBuilder();
            while (l != "-----END DSA PRIVATE KEY-----")
            {
                if (l.IndexOf(':') == -1)
                    buf.Append(l);
                else
                {
                    while (l.EndsWith("\\")) l = r.ReadLine();
                }
                l = r.ReadLine();
                if (l == null) throw new Exception(resLoader.GetString("BrokenKeyFile"));
            }

            byte[] keydata = CryptographicBuffer.DecodeFromBase64String(buf.ToString()).ToArray();
            if (passphrase != "")
            {
                r.BaseStream.Seek(0, SeekOrigin.Begin);
                r.ReadLine();//Get rid of header
                if (!r.ReadLine().StartsWith("Proc-Type: 4,ENCRYPTED"))
                    throw new Exception(resLoader.GetString("KeyFormatUnsupported"));
                String saltline = r.ReadLine();
                if (!saltline.StartsWith("DEK-Info: DES-EDE3-CBC,"))
                    throw new Exception(resLoader.GetString("KeyFormatUnsupported"));
                String saltstr = saltline.Substring(saltline.IndexOf(",") + 1).Trim();
                byte[] salt = new byte[saltstr.Length / 2];
                for (int i = 0; i < salt.Length; i++)
                    salt[i] = Convert.ToByte(saltstr.Substring(i * 2, 2), 16);
                byte[] deskey = GetOpenSSL3deskey(salt, passphrase, 1, 2);
                if (deskey == null)
                    return null;
                byte[] rsakey = DecryptKey(keydata, deskey, salt);
                keydata = rsakey;
            }
            r.Dispose();

            SSH2DataReader re = new SSH2DataReader(keydata);
            int magic = re.ReadInt16();
            if (magic != OPEN_SSH_MAGIC_VAL) throw new Exception(resLoader.GetString("BrokenKeyFile"));
            int length = re.ReadInt16();
            //Version
            re.ReadByte(); // tag: 2
            re.ReadByte(); // stored length: 1
            int version = (int)re.ReadByte(); // 0

            length = GetIntegerSize(re); // tag: 2
            BigInteger p = new BigInteger(re.Read(length));
            length = GetIntegerSize(re); // tag: 2
            BigInteger q = new BigInteger(re.Read(length));
            length = GetIntegerSize(re); // tag: 2
            BigInteger g = new BigInteger(re.Read(length));
            length = GetIntegerSize(re); // tag: 2
            BigInteger y = new BigInteger(re.Read(length));
            length = GetIntegerSize(re); // tag: 2
            BigInteger x = new BigInteger(re.Read(length));

            return new SSH2UserAuthKey(new DSAKeyPair(p, g, q, x));
        }
        public static bool IsPrivateKeyEncrypted(string filename)
        {
            bool returnVal = false;
            var fileToLaunch = StorageFile.GetFileFromPathAsync(filename);
            fileToLaunch.AsTask().Wait();
            var streamToLaunch = fileToLaunch.AsTask().Result.OpenStreamForReadAsync();
            streamToLaunch.Wait();
            using (Stream s = streamToLaunch.Result)
            {
                using (StreamReader r = new StreamReader(streamToLaunch.Result, Encoding.UTF8)) {
                    string l = r.ReadLine();
                    if (l == PKCS8_RSA_HEADER)
                    {
                        while (l != "-----END RSA PRIVATE KEY-----")
                        {
                            if (l.IndexOf("Proc-Type: 4,ENCRYPTED") != -1) 
                            {
                                returnVal = true;
                                break;
                            }
                            l = r.ReadLine();
                            if (l == null) break;
                        }
                    }
                    else if (l == PKCS8_DSA_HEADER)
                    {
                        while (l != "-----END DSA PRIVATE KEY-----")
                        {
                            if (l.IndexOf("Proc-Type: 4,ENCRYPTED") != -1)
                            {
                                returnVal = true;
                                break;
                            }
                            l = r.ReadLine();
                            if (l == null) break;
                        }
                    }
                    else if (l == SSH_COM_HEADER)
                    {
                        l = r.ReadLine();
                        StringBuilder buf = new StringBuilder();
			            while(l!="---- END SSH2 ENCRYPTED PRIVATE KEY ----") {
				            if(l.IndexOf(':')==-1)
					            buf.Append(l);
				            else {
					            while(l.EndsWith("\\")) l = r.ReadLine();
				            }
				            l = r.ReadLine();
				            if(l==null) break;
			            }
                        byte[] keydata = Base64.Decode(Encoding.UTF8.GetBytes(buf.ToString()));

			            SSH2DataReader re = new SSH2DataReader(keydata);
			            int    magic         = re.ReadInt32();
                        if (magic != SSH_COM_MAGIC_VAL) return false; // Magic number doesn't match so just say false because it will error-out anyway
			            int    privateKeyLen = re.ReadInt32();
                        byte[] tmpstr = re.ReadString();
                        string type = Encoding.UTF8.GetString(tmpstr, 0, tmpstr.Length);
                        tmpstr = re.ReadString();
                        string ciphername = Encoding.UTF8.GetString(tmpstr, 0, tmpstr.Length);
			            int    bufLen        = re.ReadInt32();
                        if (ciphername != "none")
                        {
                            returnVal = true;
                        }
                    }
                    r.Dispose();
                    s.Dispose();
                }
            }
            return returnVal;
        }
        /*
		 * Format style note
		 *  ---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
		 *  Comment: *******
		 *  <base64-encoded body>
		 *  ---- END SSH2 ENCRYPTED PRIVATE KEY ----
		 * 
		 *  body = MAGIC_VAL || body-length || type(string) || encryption-algorithm-name(string) || encrypted-body(string)
		 *  encrypted-body = array of BigInteger(algorithm-specific)
		 */
        internal static SSH2UserAuthKey FromRSAOpenSSHStyleStream(StreamReader r, string passphrase)
        {
            string l = r.ReadLine();
            StringBuilder buf = new StringBuilder();
            while (l != "-----END RSA PRIVATE KEY-----")
            {
                if (l.IndexOf(':') == -1)
                    buf.Append(l);
                else
                {
                    while (l.EndsWith("\\")) l = r.ReadLine();
                }
                l = r.ReadLine();
                if (l == null) throw new Exception(resLoader.GetString("BrokenKeyFile"));
            }
            //r.Close();

            byte[] keydata = CryptographicBuffer.DecodeFromBase64String(buf.ToString()).ToArray();
            if (passphrase != "")
            {
                r.BaseStream.Seek(0, SeekOrigin.Begin);
                r.ReadLine();//Get rid of header
                if (!r.ReadLine().StartsWith("Proc-Type: 4,ENCRYPTED"))
                    throw new Exception(resLoader.GetString("KeyFormatUnsupported"));
                String saltline = r.ReadLine();
                if (!saltline.StartsWith("DEK-Info: DES-EDE3-CBC,"))
                    throw new Exception(resLoader.GetString("KeyFormatUnsupported"));
                String saltstr = saltline.Substring(saltline.IndexOf(",") + 1).Trim();
                byte[] salt = new byte[saltstr.Length / 2];
                for (int i = 0; i < salt.Length; i++)
                    salt[i] = Convert.ToByte(saltstr.Substring(i * 2, 2), 16);
                byte[] deskey = GetOpenSSL3deskey(salt, passphrase, 1, 2);
                if (deskey == null)
                    return null;
                byte[] rsakey = DecryptKey(keydata, deskey, salt);
                keydata = rsakey;
            }
            r.Dispose();
            

            SSH2DataReader re = new SSH2DataReader(keydata);
            int magic = re.ReadInt16();
            if (magic != OPEN_SSH_MAGIC_VAL) throw new Exception(resLoader.GetString("BrokenKeyFile"));
            int length = re.ReadInt16();
            //Version
            re.ReadByte(); // tag: 2
            re.ReadByte(); // stored length: 1
            int version = (int)re.ReadByte(); // 0
            //Modulus
            length = GetIntegerSize(re); // tag: 2
            BigInteger n = new BigInteger(re.Read(length));
            length = GetIntegerSize(re); // tag: 2
            BigInteger e = new BigInteger(re.Read(length));
            length = GetIntegerSize(re); // tag: 2
            BigInteger d = new BigInteger(re.Read(length));
            length = GetIntegerSize(re); // tag: 2
            BigInteger p = new BigInteger(re.Read(length));
            length = GetIntegerSize(re); // tag: 2
            BigInteger q = new BigInteger(re.Read(length));
            //u ?? is not stored? calculated in special constructor
            /*
            length = GetIntegerSize(re); // tag: 2
            BigInteger u = re.ReadASNBigInt();
            */
            return new SSH2UserAuthKey(new RSAKeyPair(n, e, d, p, q));
        }

		/*
		 * Format style note
		 *  ---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
		 *  Comment: *******
		 *  <base64-encoded body>
		 *  ---- END SSH2 ENCRYPTED PRIVATE KEY ----
		 * 
		 *  body = MAGIC_VAL || body-length || type(string) || encryption-algorithm-name(string) || encrypted-body(string)
		 *  encrypted-body = array of BigInteger(algorithm-specific)
		 */
        internal static SSH2UserAuthKey FromSECSHStyleStream(StreamReader r, string passphrase)
        {
			string l = r.ReadLine();
			StringBuilder buf = new StringBuilder();
			while(l!="---- END SSH2 ENCRYPTED PRIVATE KEY ----") {
				if(l.IndexOf(':')==-1)
					buf.Append(l);
				else {
					while(l.EndsWith("\\")) l = r.ReadLine();
				}
				l = r.ReadLine();
                if (l == null) throw new Exception(resLoader.GetString("BrokenKeyFile"));
			}
			//r.Close();
            r.Dispose();

            byte[] keydata = Base64.Decode(Encoding.UTF8.GetBytes(buf.ToString()));

			SSH2DataReader re = new SSH2DataReader(keydata);
			int    magic         = re.ReadInt32();
            if (magic != SSH_COM_MAGIC_VAL) throw new Exception(resLoader.GetString("BrokenKeyFile"));
			int    privateKeyLen = re.ReadInt32();
            byte[] tmpstr = re.ReadString();
            string type = Encoding.UTF8.GetString(tmpstr, 0, tmpstr.Length);
            tmpstr = re.ReadString();
            string ciphername = Encoding.UTF8.GetString(tmpstr, 0, tmpstr.Length);
			int    bufLen        = re.ReadInt32();
			if(ciphername!="none") {
				CipherAlgorithm algo = CipherFactory.SSH2NameToAlgorithm(ciphername);
				byte[] key = PassphraseToKey(passphrase, CipherFactory.GetKeySize(algo));
				Cipher c = CipherFactory.CreateCipher(SSHProtocol.SSH2, algo, key);
				byte[] tmp = new Byte[re.Image.Length-re.Offset];
				c.Decrypt(re.Image, re.Offset, re.Image.Length-re.Offset, tmp, 0);
				re = new SSH2DataReader(tmp);
			}

			int parmLen          = re.ReadInt32();
			if(parmLen<0 || parmLen>re.Rest)
				throw new Exception(resLoader.GetString("WrongPassphrase"));

			if(type.IndexOf("if-modn")!=-1) {
				//mindterm mistaken this order of BigIntegers
				BigInteger e = re.ReadBigIntWithBits();
				BigInteger d = re.ReadBigIntWithBits();
				BigInteger n = re.ReadBigIntWithBits();
				BigInteger u = re.ReadBigIntWithBits();
				BigInteger p = re.ReadBigIntWithBits();
				BigInteger q = re.ReadBigIntWithBits();
				return new SSH2UserAuthKey(new RSAKeyPair(e, d, n, u, p, q));
			}
			else if(type.IndexOf("dl-modp")!=-1) {
                if (re.ReadInt32() != 0) throw new Exception(resLoader.GetString("BrokenKeyFile"));
				BigInteger p = re.ReadBigIntWithBits();
				BigInteger g = re.ReadBigIntWithBits();
				BigInteger q = re.ReadBigIntWithBits();
				BigInteger y = re.ReadBigIntWithBits();
				BigInteger x = re.ReadBigIntWithBits();
				return new SSH2UserAuthKey(new DSAKeyPair(p, g, q, y, x));
			}
			else
                throw new Exception(resLoader.GetString("KeyFormatUnknown"));

		}

		internal void WritePrivatePartInSECSHStyleFile(Stream dest, string comment, string passphrase) {
			
			//step1 key body
			SSH2DataWriter wr = new SSH2DataWriter();
			wr.Write(0); //this field is filled later
			if(_keypair.Algorithm==PublicKeyAlgorithm.RSA) {
				RSAKeyPair rsa = (RSAKeyPair)_keypair;
				RSAPublicKey pub = (RSAPublicKey)_keypair.PublicKey;
				wr.WriteBigIntWithBits(pub.Exponent);
				wr.WriteBigIntWithBits(rsa.D);
				wr.WriteBigIntWithBits(pub.Modulus);
				wr.WriteBigIntWithBits(rsa.U);
				wr.WriteBigIntWithBits(rsa.P);
				wr.WriteBigIntWithBits(rsa.Q);
			}
			else {
				DSAKeyPair dsa = (DSAKeyPair)_keypair;
				DSAPublicKey pub = (DSAPublicKey)_keypair.PublicKey;
				wr.Write(0);
				wr.WriteBigIntWithBits(pub.P);
				wr.WriteBigIntWithBits(pub.G);
				wr.WriteBigIntWithBits(pub.Q);
				wr.WriteBigIntWithBits(pub.Y);
				wr.WriteBigIntWithBits(dsa.X);
			}

			int padding_len = 0;
			if(passphrase!=null) {
				padding_len = 8 - (int)wr.Length % 8;
				wr.Write(new byte[padding_len]);
			}
			byte[] encrypted_body = wr.ToByteArray();
			SSHUtil.WriteIntToByteArray(encrypted_body, 0, encrypted_body.Length - padding_len - 4);

			//encrypt if necessary
			if(passphrase!=null) {
				Cipher c = CipherFactory.CreateCipher(SSHProtocol.SSH2, CipherAlgorithm.TripleDES, PassphraseToKey(passphrase,24));
				Debug.Assert(encrypted_body.Length % 8 ==0);
				byte[] tmp = new Byte[encrypted_body.Length];
				c.Encrypt(encrypted_body, 0, encrypted_body.Length, tmp, 0);
				encrypted_body = tmp;
			}

			//step2 make binary key data
			wr = new SSH2DataWriter();
			wr.Write(SSH_COM_MAGIC_VAL);
			wr.Write(0); //for total size
			wr.Write(_keypair.Algorithm==PublicKeyAlgorithm.RSA?
				"if-modn{sign{rsa-pkcs1-sha1},encrypt{rsa-pkcs1v2-oaep}}" :
				"dl-modp{sign{dsa-nist-sha1},dh{plain}}");

			wr.Write(passphrase==null? "none" : "3des-cbc");
			wr.WriteAsString(encrypted_body);

			byte[] rawdata = wr.ToByteArray();
			SSHUtil.WriteIntToByteArray(rawdata, 4, rawdata.Length); //fix total length

			//step3 write final data
			StreamWriter sw = new StreamWriter(dest, Encoding.UTF8);
			sw.WriteLine("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----");
			if(comment!=null)
				WriteKeyFileBlock(sw, "Comment: " + comment, true);
            byte[] tmpdata = Base64.Encode(rawdata);
            WriteKeyFileBlock(sw, Encoding.UTF8.GetString(tmpdata,0,tmpdata.Length), false);
			sw.WriteLine("---- END SSH2 ENCRYPTED PRIVATE KEY ----");
			sw.Dispose();

		}

		internal void WritePublicPartInSECSHStyle(Stream dest, string comment) {
            StreamWriter sw = new StreamWriter(dest, Encoding.UTF8);
			sw.WriteLine("---- BEGIN SSH2 PUBLIC KEY ----");
			if(comment!=null)
				WriteKeyFileBlock(sw, "Comment: " + comment, true);
			WriteKeyFileBlock(sw, FormatBase64EncodedPublicKeyBody(), false);
			sw.WriteLine("---- END SSH2 PUBLIC KEY ----");
			sw.Dispose();

		}
		internal void WritePublicPartInOpenSSHStyle(Stream dest) {
            StreamWriter sw = new StreamWriter(dest, Encoding.UTF8);
			sw.Write(SSH2Util.PublicKeyAlgorithmName(_keypair.Algorithm));
			sw.Write(' ');
			sw.WriteLine(FormatBase64EncodedPublicKeyBody());
            sw.Dispose();
		}
		private string FormatBase64EncodedPublicKeyBody() {
			SSH2DataWriter wr = new SSH2DataWriter();
			wr.Write(SSH2Util.PublicKeyAlgorithmName(_keypair.Algorithm));
			_keypair.PublicKey.WriteTo(wr);
            byte[] tmpdata = Base64.Encode(wr.ToByteArray());
            return Encoding.UTF8.GetString(tmpdata, 0, tmpdata.Length);
		}

		private static void WriteKeyFileBlock(StreamWriter sw, string data, bool escape_needed) {
			char[] d = data.ToCharArray();
			int cursor = 0;
			const int maxlen = 70;
			while(cursor < d.Length) {
				if(maxlen >= d.Length-cursor)
					sw.WriteLine(d, cursor, d.Length-cursor);
				else {
					if(escape_needed) {
						sw.Write(d, cursor, maxlen-1);
						sw.WriteLine('\\');
						cursor--;
					}
					else
						sw.WriteLine(d, cursor, maxlen);
				}

				cursor += maxlen;
			}
		}

        private static byte[] GetOpenSSL3deskey(byte[] salt, string secpswd, int count, int miter)
        {
            IntPtr unmanagedPswd = IntPtr.Zero;
            int HASHLENGTH = 16;	//MD5 bytes
            byte[] keymaterial = new byte[HASHLENGTH * miter];     //to store contatenated Mi hashed results


            byte[] psbytes = new byte[secpswd.Length];
            psbytes = Encoding.UTF8.GetBytes(secpswd);

            //UTF8Encoding utf8 = new UTF8Encoding();
            //byte[] psbytes = utf8.GetBytes(pswd);

            // --- contatenate salt and pswd bytes into fixed data array ---
            byte[] data00 = new byte[psbytes.Length + salt.Length];
            Array.Copy(psbytes, data00, psbytes.Length);		//copy the pswd bytes
            Array.Copy(salt, 0, data00, psbytes.Length, salt.Length);	//concatenate the salt bytes

            // ---- do multi-hashing and contatenate results  D1, D2 ...  into keymaterial bytes ----
            HashAlgorithmProvider md5 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5);
            byte[] result = null;
            byte[] hashtarget = new byte[HASHLENGTH + data00.Length];   //fixed length initial hashtarget

            for (int j = 0; j < miter; j++)
            {
                // ----  Now hash consecutively for count times ------
                if (j == 0)
                    result = data00;   	//initialize 
                else
                {
                    Array.Copy(result, hashtarget, result.Length);
                    Array.Copy(data00, 0, hashtarget, result.Length, data00.Length);
                    result = hashtarget;
                    //Console.WriteLine("Updated new initial hash target:") ;
                    //showBytes(result) ;
                }

                for (int i = 0; i < count; i++)
                    result = md5.HashData(result.AsBuffer()).ToArray();
                Array.Copy(result, 0, keymaterial, j * HASHLENGTH, result.Length);  //contatenate to keymaterial
            }
            //showBytes("Final key material", keymaterial);
            byte[] deskey = new byte[24];
            Array.Copy(keymaterial, deskey, deskey.Length);

            Array.Clear(psbytes, 0, psbytes.Length);
            Array.Clear(data00, 0, data00.Length);
            Array.Clear(result, 0, result.Length);
            Array.Clear(hashtarget, 0, hashtarget.Length);
            Array.Clear(keymaterial, 0, keymaterial.Length);

            return deskey;
        }

        // ----- Decrypt the 3DES encrypted RSA private key ----------

        public static byte[] DecryptKey(byte[] cipherData, byte[] desKey, byte[] IV)
        {
            MemoryStream memst = new MemoryStream();
            SymmetricKeyAlgorithmProvider alg = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.TripleDesCbcPkcs7);
            return CryptographicEngine.Decrypt(alg.CreateSymmetricKey(desKey.AsBuffer()), cipherData.AsBuffer(), IV.AsBuffer()).ToArray();
        } 
	}

}
