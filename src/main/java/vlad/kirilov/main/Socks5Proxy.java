package vlad.kirilov.main;


import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.channels.spi.SelectorProvider;
import java.util.Arrays;


public class Socks5Proxy extends Thread {

    private final int bufferSize = 8192;
    private final int port;
    private final String host;

    private static class Attachment {

        OperationType type;
        ByteBuffer in;
        ByteBuffer out;
        SelectionKey peer;
        int port;
    }

    public Socks5Proxy(String host, int port){
        this.host = host;
        this.port = port;
    }

    @Override
    public void run() {
        try {
            Selector selector = initSelector();
            while (true) {
                selector.select();
                var iterator = selector.selectedKeys().iterator();
                while (iterator.hasNext()) {
                    SelectionKey key = iterator.next();
                    iterator.remove();
                    handleKey(key);
                }
            }
        } catch (IOException e) {
        }
    }

    private Selector initSelector() throws IOException{
        Selector selector = SelectorProvider.provider().openSelector();
        ServerSocketChannel serverChannel = ServerSocketChannel.open();
        serverChannel.configureBlocking(false);
        serverChannel.socket().bind(new InetSocketAddress(host,port));
        serverChannel.register(selector,serverChannel.validOps());
        return selector;
    }

    private void handleKey(SelectionKey key) throws IOException{
        if (key.isValid()) {
            try {
                if (key.isAcceptable()) {
                    accept(key);
                } else if (key.isConnectable()) {
                    connect(key);
                } else if (key.isReadable()) {
                        read(key);
                } else if (key.isWritable()) {
                    write(key);
                }
            } catch (Exception e) {
                close(key);
            }
        }
    }
    private void accept(SelectionKey key) throws IOException {
       ServerSocketChannel serverSocketChannel = (ServerSocketChannel) key.channel();
       SocketChannel channel = serverSocketChannel.accept();
       channel.configureBlocking(false);
       channel.register(key.selector(),SelectionKey.OP_READ);

    }

    private void read(SelectionKey key) throws IOException {
        var attachment = (Attachment)key.attachment();
        if (attachment == null) {
            attachment= new Attachment();
            attachment.in = ByteBuffer.allocate(bufferSize);
            attachment.type = OperationType.AUTH_READ;
            key.attach(attachment);
        }

        if (attachment.type == OperationType.DNS_READ ) {
            var channel = (DatagramChannel) key.channel();
            if (channel.read(attachment.in) <= 0) {
                close(key);
                throw new IOException("Invalid DNS reply");
            } else {
                var message = new Message(attachment.in.array());
                var maybeRecord = message.getSection(Section.ANSWER).stream().findAny();
                if (maybeRecord.isPresent()) {
                    var ipAddr = InetAddress.getByName(maybeRecord.get().rdataToString());
                    registerPeer(ipAddr, attachment.port, attachment.peer);
                    key.interestOps(0);
                    key.cancel();
                    key.channel().close();
                } else {

                    close(key);
                    throw new RuntimeException("Host cannot be resolved");
                }
            }

        } else {
            SocketChannel channel = (SocketChannel) key.channel();

            if (channel.read(attachment.in) <= 0) {
                close(key);
            } else if (attachment.type == OperationType.AUTH_READ) {
                readAndRequestAuthMessage(key);
            } else if (attachment.peer == null) {
                readAndRequestConnectionMessage(key);

            } else {
                attachment.peer.interestOps(attachment.peer.interestOps() | SelectionKey.OP_WRITE);
                key.interestOps(key.interestOps() ^ SelectionKey.OP_READ);
                attachment.in.flip();
            }
        }
    }

    private void readAndRequestAuthMessage(SelectionKey key) throws IllegalStateException{
        var attachment = (Attachment)key.attachment();

        byte[] buffer = attachment.in.array();

        if (buffer[0] != Socks5Utils.VERSION) {
            return;
        }

        int methodsCount = buffer[1];


        boolean isNoAuthMethodFound = false;
        for (int i = 0; i < methodsCount; i++) {
            var method = buffer[i + 2];
            if (method == Socks5Utils.NO_AUTH) {
                isNoAuthMethodFound = true;
                break;
            }
        }

        if (!isNoAuthMethodFound) {
            throw new RuntimeException("Auth request has no no auth method, only no auth method is supported");
        }


        attachment.out = attachment.in;
        attachment.out.clear();
        attachment.out.put(Socks5Utils.AUTH_NO_AUTH_REPLY).flip();
        attachment.type = OperationType.AUTH_WRITE;
        key.interestOps(SelectionKey.OP_WRITE);
    }

    private void readAndRequestConnectionMessage(SelectionKey key) throws IOException {

        var attachment = (Attachment) key.attachment();
        var len = attachment.in.position();
        if (len < 4) {
            return;
        }

        var buffer = attachment.in.array();
        if (buffer[0] != Socks5Utils.VERSION) {
            throw new RuntimeException("Connection request has invalid version, only SOCKS5 is supported");
        }

        if (buffer[1] != Socks5Utils.CONNECTION_COMMAND) {
            throw new RuntimeException("0x%02x command is not supported, only 0x01 (connect) is supported");
        }

        if (buffer[3] == Socks5Utils.ADDR_TYPE_IPV4) {
            var connectAddrBytes = new byte[]{buffer[4], buffer[5], buffer[6], buffer[7]};
            var connectAddr = InetAddress.getByAddress(connectAddrBytes);
            var portPos = 8;
            var connectPort = ((buffer[portPos] & 0xFF) << 8) + (buffer[portPos + 1] & 0xFF);

            registerPeer(connectAddr, connectPort, key);
            key.interestOps(0);
        } else if (buffer[3] == Socks5Utils.ADDR_TYPE_HOST) {
            var hostLen = buffer[4];
            var hostStart = 5;

            var host = new String(Arrays.copyOfRange(buffer, hostStart, hostStart + hostLen));
            var portPos = hostStart + hostLen;
            var connectPort = ((buffer[portPos] & 0xFF) << 8) + (buffer[portPos + 1] & 0xFF);


            key.interestOps(0);

            requestHostResolve(host, connectPort, key);
        }
    }

    private void registerPeer(InetAddress connectAddr, int connectPort, SelectionKey backKey) throws IOException {

        var peer = SocketChannel.open();
        peer.configureBlocking(false);
        peer.connect(new InetSocketAddress(connectAddr, connectPort));
        var peerKey = peer.register(backKey.selector(), SelectionKey.OP_CONNECT);

        ((Attachment) backKey.attachment()).peer = peerKey;
        Attachment peerAttachment = new Attachment();
        peerAttachment.peer = backKey;
        peerKey.attach(peerAttachment);

        ((Attachment) backKey.attachment()).in.clear();
    }

    private void requestHostResolve(String host, int backPort, SelectionKey backKey) throws IOException {
        var peer = DatagramChannel.open();
        peer.connect(ResolverConfig.getCurrentConfig().server());
        peer.configureBlocking(false);

        var key = peer.register(backKey.selector(), SelectionKey.OP_WRITE);

        Attachment attachment = new Attachment();
        attachment.type = OperationType.DNS_WRITE;
        attachment.port = backPort;
        attachment.peer = backKey;
        attachment.in = ByteBuffer.allocate(bufferSize);

        var message = new Message();
        var record = Record.newRecord(Name.fromString(host + '.').canonicalize(), org.xbill.DNS.Type.A, DClass.IN);
        message.addRecord(record, Section.QUESTION);

        var header = message.getHeader();

        header.setFlag(Flags.AD);
        header.setFlag(Flags.RD);

        attachment.in.put(message.toWire());
        attachment.in.flip();
        attachment.out = attachment.in;

        key.attach(attachment);

    }
    private void connect(SelectionKey key) throws IOException {
        SocketChannel channel =  (SocketChannel)key.channel();
        Attachment attachment = ((Attachment) key.attachment());
        channel.finishConnect();

        attachment.in = ByteBuffer.allocate(bufferSize);
        attachment.in.put(Socks5Utils.CONNECTION_OK_REPLY).flip();
        attachment.out = ((Attachment) attachment.peer.attachment()).in;
        ((Attachment) attachment.peer.attachment()).out = attachment.in;
        attachment.peer.interestOps(SelectionKey.OP_WRITE | SelectionKey.OP_READ);
        key.interestOps( 0 );
    }

    private void write(SelectionKey key) throws IOException {

      Attachment attachment = (Attachment) key.attachment();

        if (attachment.type == OperationType.DNS_WRITE) {
            var channel = ((DatagramChannel) key.channel());


            if (channel.write(attachment.out) == -1) {
                close(key);
            } else if (attachment.out.remaining() == 0) {

                attachment.out.clear();
                attachment.type = OperationType.DNS_READ;
                key.interestOpsOr(SelectionKey.OP_READ);
                key.interestOpsAnd(~SelectionKey.OP_WRITE);
            }
        } else {
            SocketChannel channel = (SocketChannel) key.channel();
            ByteBuffer buffer = attachment.out;
            if (channel.write(buffer) == -1) {
                close(key);
            } else if (buffer.remaining() == 0) {
                if (attachment.type == OperationType.AUTH_WRITE) {

                    attachment.out.clear();
                    key.interestOps(SelectionKey.OP_READ);
                    attachment.type = OperationType.READ;
                } else if (attachment.peer == null) {
                    close(key);
                } else {
                    attachment.out.clear();
                    attachment.peer.interestOps(attachment.peer.interestOps() | SelectionKey.OP_READ);
                    key.interestOps(key.interestOps() ^ SelectionKey.OP_WRITE);
                }
            }
        }

    }



    private void close(SelectionKey key) throws IOException {
        key.cancel();
        key.channel().close();
        SelectionKey peerKey = ((Attachment) key.attachment()).peer;
        if (peerKey != null) {
            ((Attachment)peerKey.attachment()).peer=null;
            if((peerKey.interestOps()&SelectionKey.OP_WRITE) == 0 ) {
                ((Attachment)peerKey.attachment()).out.flip();
            }
            peerKey.interestOps(SelectionKey.OP_WRITE);
        }
    }
}
