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
using System.Diagnostics;
//using System.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Security.Cryptography;
using System.Runtime.InteropServices.WindowsRuntime;

namespace GranadosRT.Routrek.PKI
{

	public interface ISigner {
        byte[] Sign([ReadOnlyArray()] byte[] data);
	}
	public interface IVerifier {
        void Verify([ReadOnlyArray()] byte[] data, [WriteOnlyArray()] byte[] expected);
	}

	internal interface IKeyWriter {
		void Write(BigInteger bi);
	}

	
	public enum PublicKeyAlgorithm {
		DSA,
		RSA
	}

	internal interface PublicKey {
		void WriteTo(IKeyWriter writer);
        PublicKeyAlgorithm Algorithm { get; }
	}

    internal interface KeyPair
    {
		
		PublicKey PublicKey { get; }
        PublicKeyAlgorithm Algorithm { get; }
	}

	public sealed class PKIUtil {
		// OID { 1.3.14.3.2.26 }
		// iso(1) identified-org(3) OIW(14) secsig(3) alg(2) sha1(26)
		internal static readonly byte[] SHA1_ASN_ID = new byte[] { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
	}
    /*
	public class VerifyException : Exception {
		public VerifyException(string msg) : base(msg) {}
	}
    */

}
