package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	rand "crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	tls "github.com/libp2p/go-libp2p/p2p/transport/tls"

	kyber "github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/core/log"
	libp2p "github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	peer "github.com/libp2p/go-libp2p/core/peer"
	swarm "github.com/libp2p/go-libp2p/p2p/net/swarm"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	webrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	ma "github.com/multiformats/go-multiaddr"
)

// _____________________________________________ quantum encryption

func generateQuantumKeys() (*kyber.PublicKey, *kyber.PrivateKey) {
	public, private, err := kyber.GenerateKeyPair(rand.Reader)
	_ = err
	return public, private
}

var quantumPublicKey, quantumPrivateKey = generateQuantumKeys()

type ProtocolHandler struct {
	QUIC   network.StreamHandler
	WebRTC network.StreamHandler
	TLS    network.StreamHandler
}

func NewProtocolHandler() *ProtocolHandler {
	return &ProtocolHandler{
		QUIC:   handleQUICStream,
		WebRTC: handleWebRTCStream,
		TLS:    handleTLSStream,
	}
}

type WebRTCPeer struct {
	PeerID      string
	Connection  *webrtc.ListenUDPFn
	DataChannel *webrtc.WebRTCTransport
}

type WebRTCSignal struct {
	Type   string `json:"type"`
	SDP    string `json:"sdp,omitempty"`
	ICE    string `json:"ice,omitempty"`
	PeerID string `json:"peerId"`
}

// ───────────────────────────────────────────── dial‑ranking

func preferQUIC(addrs []ma.Multiaddr) []network.AddrDelay {
	var result []network.AddrDelay

	for _, addr := range addrs {
		if strings.Contains(addr.String(), "quic") || strings.Contains(addr.String(), "webrtc") {
			result = append(result, network.AddrDelay{
				Addr:  addr,
				Delay: 0,
			})
		} else {
			result = append(result, network.AddrDelay{
				Addr:  addr,
				Delay: 100 * time.Millisecond,
			})
		}
	}

	return result
}

func handleQUICStream(s network.Stream) {
	defer s.Close()
	// Your existing handleStream logic for QUIC
	buf := bufio.NewReader(s)
	ct, _ := buf.ReadBytes('\n')
	msg_decrypt := decryptMessage(ct, quantumPrivateKey)
	fmt.Println("QUIC: decrypted message: ", msg_decrypt)
}

func handleWebRTCStream(s network.Stream) {
	defer s.Close()
	decoder := json.NewDecoder(s)
	var signal WebRTCSignal
	if err := decoder.Decode(&signal); err != nil {
		log.Printf("WebRTC: Failed to decode signal: %v", err)
		return
	}
	if signal.SDP != "" {
		decryptedSDP := decryptMessage([]byte(signal.SDP), quantumPrivateKey)
		signal.SDP = string(decryptedSDP)
	}
	if signal.ICE != "" {
		decryptedICE := decryptMessage([]byte(signal.ICE), quantumPrivateKey)
		signal.ICE = string(decryptedICE)
	}
	// Handle WebRTC signaling
	fmt.Println("WebRTC: received signaling message from", s.Conn().RemotePeer())
}

func handleTLSStream(s network.Stream) {
	defer s.Close()
	// TLS-specific handling
	buf := bufio.NewReader(s)
	ct, _ := buf.ReadBytes('\n')
	msg_decrypt := decryptMessage(ct, quantumPrivateKey)
	fmt.Println("TLS: decrypted message: ", msg_decrypt)
}

func encryptMessage(msg []byte, recipientPubKey *kyber.PublicKey) []byte {
	ciphertext, sharedSecret, err := kyber.Scheme().Encapsulate(recipientPubKey)
	if err != nil {
		return nil
	}

	block, err := aes.NewCipher(sharedSecret[:32])
	if err != nil {
		return nil
	}

	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	encryptedMsg := gcm.Seal(nonce, nonce, msg, nil)

	result := append(ciphertext, encryptedMsg...)
	return result
}

func decryptMessage(ct []byte, recipientPrivKey *kyber.PrivateKey) string {
	ciphertextSize := kyber.Scheme().CiphertextSize()
	if len(ct) < ciphertextSize {
		return ""
	}

	ciphertext := ct[:ciphertextSize]
	encryptedMsg := ct[ciphertextSize:]

	sharedSecret, err := kyber.Scheme().Decapsulate(recipientPrivKey, ciphertext)
	if err != nil {
		return ""
	}

	block, err := aes.NewCipher(sharedSecret[:32])
	if err != nil {
		return ""
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}

	if len(encryptedMsg) < gcm.NonceSize() {
		return ""
	}
	nonce := encryptedMsg[:gcm.NonceSize()]
	ciphertextMsg := encryptedMsg[gcm.NonceSize():]

	plain, err := gcm.Open(nil, nonce, ciphertextMsg, nil)
	if err != nil {
		return ""
	}

	return string(plain)
}

type Message struct {
	message string
}

func createMessage(msgText string) []byte {
	message := Message{message: msgText}
	msg := []byte(message.message)
	return msg
}

func peerSend(host host.Host, kad *dht.IpfsDHT, ctx context.Context, peerIDStr string) {
	pid, err := peer.Decode(peerIDStr)
	if err != nil {
		log.Fatal("invalid peer ID:", err)
	}
	info, err := kad.FindPeer(ctx, pid)
	if err != nil {
		log.Fatal("DHT lookup failed:", err)
	}

	if err = host.Connect(ctx, info); err != nil {
		log.Fatal("dial failed:", err)
	}

	stream, err := host.NewStream(ctx, pid)
	if err != nil {
		log.Printf("Failed to create %s stream: %v", err)
		createMixNet()
	}

	protocol, err := host.Peerstore().FirstSupportedProtocol(pid)
	if err != nil {
		log.Printf("Failed to get peer protocols: %v", err)
	} else {
		fmt.Printf("Peer supports protocols: %v\n", protocol)
	}

	switch protocol {
	case "/webrtc/1.0.0":
		// WebRTC signaling
		signal := WebRTCSignal{
			Type:   "offer",
			SDP:    "your_sdp_data",
			ICE:    "your_ice_data",
			PeerID: host.ID().String(),
		}
		if signal.SDP != "" {
			encryptedSDP := encryptMessage([]byte(signal.SDP), quantumPublicKey)
			signal.SDP = string(encryptedSDP)
		}
		if signal.ICE != "" {
			encryptedICE := encryptMessage([]byte(signal.ICE), quantumPublicKey)
			signal.ICE = string(encryptedICE)
		}

		json.NewEncoder(stream).Encode(signal)

	default:
		// Regular message encryption for QUIC/TLS
		msgText := "hello world"
		msg := createMessage(msgText)
		result := encryptMessage(msg, quantumPublicKey)
		stream.Write(result)
		if stream == nil {
			createMixNet()
		}
	}
}

func peerListen(host host.Host) {
	handlers := NewProtocolHandler()
	// Set up protocol-specific handlers
	host.SetStreamHandler("/quic/1.0.0", handlers.QUIC)
	host.SetStreamHandler("/webrtc/1.0.0", handlers.WebRTC)
	host.SetStreamHandler("/tls/1.0.0", handlers.TLS)

	select {}
}

// ───────────────────────────────────────────── main
func main() {
	ctx := context.Background()

	isPrivKey, _, _ := crypto.GenerateEd25519Key(rand.Reader)
	host, _ := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/udp/9000/quic-v1"),
		libp2p.Identity(isPrivKey),
		libp2p.Transport(quic.NewTransport),
		libp2p.Transport(webrtc.New),
		libp2p.Transport(tls.New),
		libp2p.SwarmOpts(swarm.WithDialRanker(preferQUIC)),
	)
	fmt.Println("★ I am", host.ID())
	for _, a := range host.Addrs() {
		fmt.Println("  listening on", a)
	}
	kad, _ := dht.New(ctx, host, dht.Mode(dht.ModeClient))

	peerListen(host)
	peerSend(host, kad, ctx, host.ID().String())

}
