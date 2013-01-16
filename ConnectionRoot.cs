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
using System.Collections;
using System.Collections.Generic;
using System.IO;
using Windows.Networking;
using Windows.Networking.Sockets;
using System.Text;
using GranadosRT.Routrek.Crypto;
using GranadosRT.Routrek.PKI;
using GranadosRT.Routrek.SSHCV1;
using GranadosRT.Routrek.SSHCV2;
using System.Runtime.InteropServices.WindowsRuntime;

namespace GranadosRT.Routrek.SSHC
{
	public interface SSHConnection {




        SSHConnectionInfo ConnectionInfo();
		
		/**
		* returns true if any data from server is available
		*/
        bool Available();

        SSHConnectionParameter Param();
        AuthenticationResult AuthenticationResult();
        IByteArrayHandler PacketBuilder();
        ISSHConnectionEventReceiver EventReceiver();
        int ChannelCount();

        bool IsClosed();
        bool AutoDisconnect();


		AuthenticationResult DoConnect(AbstractSocket target);

		/**
		* terminates this connection
		*/
        void Disconnect(string msg);
        void RegisterChannel(int local_id, SSHChannel ch);
        void UnregisterChannelEventReceiver(int id);
		/**
		* opens a pseudo terminal
		*/
        SSHChannel OpenShell(ISSHChannelEventReceiver receiver);

		/**
		 * forwards the remote end to another host
		 */
        SSHChannel ForwardPort(ISSHChannelEventReceiver receiver, string remote_host, int remote_port, string originator_host, int originator_port);

		/**
		 * listens a connection on the remote end
		 */
        void ListenForwardedPort(string allowed_host, int bind_port);

		/**
		 * cancels binded port
		 */
        void CancelForwardedPort(string host, int port);

		/**
		* closes socket directly.
		*/
		void Close();


        void SendIgnorableData(string msg);


    }

	public enum ChannelType {
		Session,
		Shell,
		ForwardedLocalToRemote,
		ForwardedRemoteToLocal
	}
    public interface SSHChannel
    {
        /**
		 * resizes the size of terminal
		 */
        void ResizeTerminal(int width, int height, int pixel_width, int pixel_height);

        /**
        * transmits channel data 
        */
        void Transmit([ReadOnlyArray()] byte[] data);

        /**
        * transmits channel data 
        */
        void Transmit([ReadOnlyArray()] byte[] data, int offset, int length);

        /**
         * sends EOF(SSH2 only)
         */
        void SendEOF();

        /**
         * closes this channel
         */
        void Close();

        int LocalChannelID();
 
        int RemoteChannelID();

        SSHConnection Connection();

        ChannelType Type();

    }
}
