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
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Foundation;

namespace GranadosRT.Routrek.SSHC
{
	//param connectionInfo is identical to the ConnectionInfo property of the connection 
	public delegate bool HostKeyCheckCallback(SSHConnectionInfo connectionInfo);

	//port forwarding check result
	public sealed class PortForwardingCheckResult {
		/**
		 * if you allow this request, set 'allowed' to true.
		 */
        internal bool allowed;

		/**
		 * if you allow this request, you must set 'channel' for this request. otherwise, 'channel' is ignored
		 */
        internal ISSHChannelEventReceiver channel;

		/**
		 * if you disallow this request, you can set 'reason_code'.
			The following reason codes are defined:

			#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED    1
			#define SSH_OPEN_CONNECT_FAILED                 2
			#define SSH_OPEN_UNKNOWN_CHANNEL_TYPE           3
			#define SSH_OPEN_RESOURCE_SHORTAGE              4
		 */
        internal int reason_code;

		/**
		 * if you disallow this request, you can set 'reason_message'. this message can contain only ASCII characters.
		 */
        internal string reason_message;
	}

	/// <summary>
	/// Connection specific receiver
	/// </summary>
    public interface ISSHConnectionEventReceiver
    {
		void OnDebugMessage(bool always_display, [ReadOnlyArray()] byte[] msg);
        void OnIgnoreMessage([ReadOnlyArray()] byte[] msg);
        void OnUnknownMessage(byte type, [ReadOnlyArray()] byte[] data);
		void OnError(Exception error, string msg);
		void OnConnectionClosed();
        void OnAuthenticationPrompt([ReadOnlyArray()] string[] prompts); //keyboard-interactive only
        PortForwardingCheckResult CheckPortForwardingRequest(string remote_host, int remote_port, string originator_ip, int originator_port);
		void EstablishPortforwarding(ISSHChannelEventReceiver receiver, SSHChannel channel);
	}

	/// <summary>
	/// Channel specific receiver 
	/// </summary>
	public interface ISSHChannelEventReceiver {
        //IAsyncAction OnData([ReadOnlyArray()] byte[] data, int offset, int length);
        void OnData([ReadOnlyArray()] byte[] data, int offset, int length);
        void OnExtendedData(int type, [ReadOnlyArray()] byte[] data);
		void OnChannelClosed();
		void OnChannelEOF();
		void OnChannelError(Exception error, string msg);
		void OnChannelReady();
        void OnMiscPacket(byte packet_type, [ReadOnlyArray()] byte[] data, int offset, int length);
	}

}
