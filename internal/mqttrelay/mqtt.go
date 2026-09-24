// Package mqttrelay is the primary no-port-forward transport: both sides
// dial OUT to a public MQTT broker (persistent TCP 1883, zero polling).
// It exists because public ntfy hosts banned this IP after our old hot-poll
// loop (~150 req/min); MQTT holds ONE connection with a 30s keepalive.
//
// Topics (Base = rmm/1762299854):
//   - Base/hello            agent connect announces (controller subscribes)
//   - Base/out/<host>       agent data: output/screen/mouse/pong
//   - Base/cmd/<host>       controller commands to one agent
//   - Base/cmd/all          controller broadcasts (currently unused)
//   - Base/presence         controller heartbeats (controllers subscribe;
//                             agents never see it; peer count = HA visibility)
// Payloads are relay.Envelope JSON (same shape as the ntfy path, so all
// routing/To-filtering code is shared). QoS 0 + clean session everywhere:
// drops beat duplicates/replays for screens and mouse; commands are
// user-retried and therefore self-healing.
package mqttrelay

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
	"rmm/internal/relay"
)

var (
	// TLS-only brokers (no username/password): every relay byte is
	// encrypted in transit. Verification stays ON (InsecureSkipVerify is
	// never set) so this is real encryption, not just obfuscation.
	// Sticky priority order (first reachable wins) so all processes meet
	// on the same broker. A latency race was tried and caused chronic
	// split-brain; failures cool down 5 minutes, then rejoin the order.
	Brokers = []string{
		"ssl://broker.emqx.io:8883",
		"ssl://broker.hivemq.com:8883",
		// WebSocket-TLS fallback on 443-ish ports: when a firewall kills
		// raw 8883, MQTT-over-WSS usually still passes. Tried last (more
		// overhead than raw TLS) and skipped automatically when unreachable.
		"wss://broker.emqx.io:8084/mqtt",
	}
	// NOTE: test.mosquitto.org:8883 was dropped: its chain does not verify
	// against the Windows root store (unknown authority), and unverified
	// TLS is worse than no entry. Two verified brokers + WSS fallback +
	// direct + ntfy keep redundancy intact.
	// Base is the topic root. Keep in sync on both sides.
	Base = "rmm/1762299854"
)

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func dial(broker, clientID string, onConnect paho.OnConnectHandler) (paho.Client, error) {
	opts := paho.NewClientOptions()
	opts.AddBroker(broker)
	opts.SetClientID(clientID)
	opts.SetCleanSession(true)
	opts.SetAutoReconnect(true)
	opts.SetMaxReconnectInterval(30 * time.Second)
	opts.SetConnectTimeout(5 * time.Second)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetPingTimeout(10 * time.Second)
	if strings.HasPrefix(broker, "ssl://") || strings.HasPrefix(broker, "tls://") || strings.HasPrefix(broker, "wss://") {
		opts.SetTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12})
	}
	opts.SetOnConnectHandler(onConnect)
	opts.SetConnectionLostHandler(func(_ paho.Client, err error) {
		log.Printf("[mqtt] connection lost (%s): %v", broker, err)
	})
	c := paho.NewClient(opts)
	if token := c.Connect(); token.WaitTimeout(8*time.Second) && token.Error() != nil {
		return nil, token.Error()
	} else if token.Error() != nil {
		return nil, fmt.Errorf("connect timeout")
	}
	return c, nil
}

func publish(c paho.Client, topic string, env relay.Envelope) error {
	return publishTimeout(c, topic, env, 10*time.Second)
}

// publishTimeout bounds one QoS0 publish. Bulk payloads (file/update
// chunks) keep 10s; interactive frames (screen/mouse/audio, small commands)
// fail fast at 2s so one wedged broker hop never head-of-line blocks the
// pipe behind it (loss is idempotent: fseq drops stale screens, CmdID
// dedupes commands, audio gap-resets).
func publishTimeout(c paho.Client, topic string, env relay.Envelope, d time.Duration) error {
	body, _ := json.Marshal(env)
	token := c.Publish(topic, 0, false, body)
	if !token.WaitTimeout(d) {
		return fmt.Errorf("publish timeout")
	}
	return token.Error()
}

func subscribe(c paho.Client, topic string, handle func(env relay.Envelope)) error {
	token := c.Subscribe(topic, 0, func(_ paho.Client, m paho.Message) {
		var env relay.Envelope
		if err := json.Unmarshal(m.Payload(), &env); err != nil {
			return
		}
		handle(env)
	})
	if !token.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("subscribe timeout")
	}
	return token.Error()
}

// AgentBus is the agent side of the MQTT transport.
type AgentBus struct {
	client paho.Client
	broker string
	host   string
}

var (
	brokerMu       sync.Mutex
	cachedBroker   string
	brokerCooldown = map[string]int64{} // broker -> unixnano until which it is skipped
)

func noteBrokerFailure(b string) {
	brokerMu.Lock()
	defer brokerMu.Unlock()
	if b == cachedBroker {
		cachedBroker = ""
	}
	brokerCooldown[b] = time.Now().Add(5 * time.Minute).UnixNano()
}

// raceDial picks a healthy broker with sticky priority order (first
// reachable wins) so every process converges on the SAME broker —
// rendezvous requires it, since publishers and subscribers only meet when
// they share one. A parallel race by latency was tried and caused chronic
// split-brain (agent on emqx, controller on hivemq, silence both ways).
// Failed brokers cool down 5 minutes, then rejoin the order.
func raceDial(idPrefix string) (paho.Client, string, error) {
	return raceDialExcept(idPrefix, "", true)
}

// raceDialExcept is raceDial that skips one broker (the controller's second
// bus listens on a DIFFERENT broker so agents are heard no matter which
// broker they picked — split-brain is impossible when you listen on both).
// With useCache=false the shared sticky cache is left untouched.
func raceDialExcept(idPrefix, skip string, useCache bool) (paho.Client, string, error) {
	brokerMu.Lock()
	cached, cooled := cachedBroker, brokerCooldown[cachedBroker] > time.Now().UnixNano()
	brokerMu.Unlock()
	if useCache && cached != "" && !cooled && cached != skip {
		id := fmt.Sprintf("%s-%s", idPrefix, randHex(3))
		if c, err := dial(cached, id, nil); err == nil {
			return c, cached, nil
		}
		noteBrokerFailure(cached)
	}
	now := time.Now().UnixNano()
	brokerMu.Lock()
	var cands []string
	for _, b := range Brokers {
		if b != skip && brokerCooldown[b] <= now {
			cands = append(cands, b)
		}
	}
	brokerMu.Unlock()
	if len(cands) == 0 {
		return nil, "", fmt.Errorf("all brokers cooling down")
	}
	var lastErr error
	for _, b := range cands {
		id := fmt.Sprintf("%s-%s", idPrefix, randHex(3))
		t := time.Now()
		c, err := dial(b, id, nil)
		if err != nil {
			log.Printf("[mqtt] %s unreachable: %v", b, shortErr(err))
			noteBrokerFailure(b)
			lastErr = err
			continue
		}
		if useCache {
			brokerMu.Lock()
			cachedBroker = b
			brokerMu.Unlock()
		}
		log.Printf("[mqtt] broker %s (%s)", b, time.Since(t).Round(time.Millisecond))
		return c, b, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no brokers reachable")
	}
	return nil, "", lastErr
}

// DialControllerExcept connects through the first healthy broker that is
// NOT skip (the controller's secondary listener). Shares failure/cooldown
// tracking but never disturbs the sticky primary cache.
func DialControllerExcept(skip string) (*CtrlBus, error) {
	c, broker, err := raceDialExcept("rmm-ctrl2", skip, false)
	if err != nil {
		return nil, err
	}
	log.Printf("[mqtt] controller secondary via %s", broker)
	return &CtrlBus{client: c, broker: broker}, nil
}

// DialAgent connects through the fastest healthy broker.
func DialAgent(hostname string) (*AgentBus, error) {
	c, broker, err := raceDial("rmm-agent-" + sanitize(hostname))
	if err != nil {
		return nil, err
	}
	log.Printf("[mqtt] agent connected via %s", broker)
	return &AgentBus{client: c, broker: broker, host: hostname}, nil
}

// SubscribeCmd subscribes to our directed topic plus broadcasts.
// Resubscribes automatically after reconnects.
func (b *AgentBus) SubscribeCmd(handle func(env relay.Envelope)) error {
	topics := map[string]byte{
		Base + "/cmd/" + b.host: 0,
		Base + "/cmd/all":        0,
	}
	token := b.client.SubscribeMultiple(topics, func(_ paho.Client, m paho.Message) {
		var env relay.Envelope
		if err := json.Unmarshal(m.Payload(), &env); err != nil {
			return
		}
		handle(env)
	})
	if !token.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("subscribe timeout")
	}
	if err := token.Error(); err != nil {
		return err
	}
	// paho auto-resubscribes SubscribeMultiple topics on reconnect.
	return nil
}

// Publish sends to Base/suffix (e.g. "out/<host>", "hello").
func (b *AgentBus) Publish(suffix string, env relay.Envelope) error {
	return publish(b.client, Base+"/"+suffix, env)
}

// PublishBin publishes raw bytes to Base/suffix (binary media topics:
// no JSON/base64 framing). Fast 2s cap like PublishFast.
func (b *AgentBus) PublishBin(suffix string, body []byte) error {
	token := b.client.Publish(Base+"/"+suffix, 0, false, body)
	if !token.WaitTimeout(2 * time.Second) {
		return fmt.Errorf("publish timeout")
	}
	return token.Error()
}

// PublishFast is Publish with a 2s cap for small interactive frames
// (screen/tile/mouse/audio). Bulk chunk senders keep Publish (10s).
func (b *AgentBus) PublishFast(suffix string, env relay.Envelope) error {
	return publishTimeout(b.client, Base+"/"+suffix, env, 2*time.Second)
}

func (b *AgentBus) Close() { b.client.Disconnect(500) }

// Broker reports which broker this bus is connected through (diagnostics).
func (b *AgentBus) Broker() string { return b.broker }

// CtrlBus is the controller side of the MQTT transport.
type CtrlBus struct {
	client paho.Client
	broker string
}

// DialController connects through the fastest healthy broker.
func DialController() (*CtrlBus, error) {
	c, broker, err := raceDial("rmm-ctrl")
	if err != nil {
		return nil, err
	}
	log.Printf("[mqtt] controller connected via %s", broker)
	return &CtrlBus{client: c, broker: broker}, nil
}

// Subscribe registers hello + all agent outputs + live audio chunks +
// controller presence. Topic is passed so the controller can route
// (hello vs out/<host> vs audio/<host> vs presence).
func (b *CtrlBus) Subscribe(handle func(topic string, env relay.Envelope)) error {
	topics := map[string]byte{
		Base + "/hello":   0,
		Base + "/out/+":   0,
		Base + "/audio/+": 0,
		Base + "/presence": 0,
	}
	token := b.client.SubscribeMultiple(topics, func(_ paho.Client, m paho.Message) {
		var env relay.Envelope
		if err := json.Unmarshal(m.Payload(), &env); err != nil {
			return
		}
		handle(m.Topic(), env)
	})
	if !token.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("subscribe timeout")
	}
	return token.Error()
}

// SubscribeBin registers the binary media topic (audiobin/<host>): raw
// frames, no envelope. Runs alongside Subscribe; the controller routes by
// topic prefix.
func (b *CtrlBus) SubscribeBin(handle func(topic string, body []byte)) error {
	token := b.client.Subscribe(Base+"/audiobin/+", 0, func(_ paho.Client, m paho.Message) {
		handle(m.Topic(), m.Payload())
	})
	if !token.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("subscribe timeout")
	}
	return token.Error()
}

// PublishCmd sends a directed command to one agent host.
func (b *CtrlBus) PublishCmd(host string, env relay.Envelope) error {
	return publish(b.client, Base+"/cmd/"+host, env)
}

// PublishCmdFast is PublishCmd with a 2s cap for small interactive orders
// (screenshot requests, pings, small commands, manifests). Bulk chunks
// keep the 10s PublishCmd.
func (b *CtrlBus) PublishCmdFast(host string, env relay.Envelope) error {
	return publishTimeout(b.client, Base+"/cmd/"+host, env, 2*time.Second)
}

// PublishPresence broadcasts a controller heartbeat (peer visibility for
// multi-controller HA). Only controllers subscribe; agents never see it.
func (b *CtrlBus) PublishPresence(env relay.Envelope) error {
	return publish(b.client, Base+"/presence", env)
}

func (b *CtrlBus) Close() { b.client.Disconnect(500) }

// Broker reports which broker this bus is connected through (diagnostics).
func (b *CtrlBus) Broker() string { return b.broker }

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}
