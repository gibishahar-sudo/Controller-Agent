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
// Payloads are relay.Envelope JSON (same shape as the ntfy path, so all
// routing/To-filtering code is shared). QoS 0 + clean session everywhere:
// drops beat duplicates/replays for screens and mouse; commands are
// user-retried and therefore self-healing.
package mqttrelay

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
	"rmm/internal/relay"
)

var (
	// Brokers in priority order; Dial tries each with a 5s timeout.
	Brokers = []string{
		"tcp://broker.emqx.io:1883",
		"tcp://test.mosquitto.org:1883",
		"tcp://broker.hivemq.com:1883",
	}
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
	body, _ := json.Marshal(env)
	token := c.Publish(topic, 0, false, body)
	if !token.WaitTimeout(10 * time.Second) {
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

// DialAgent connects to the first reachable broker.
func DialAgent(hostname string) (*AgentBus, error) {
	var lastErr error
	for _, broker := range Brokers {
		id := fmt.Sprintf("rmm-agent-%s-%s", sanitize(hostname), randHex(3))
		c, err := dial(broker, id, nil)
		if err != nil {
			log.Printf("[mqtt] %s unreachable: %v", broker, shortErr(err))
			lastErr = err
			continue
		}
		log.Printf("[mqtt] agent connected via %s", broker)
		return &AgentBus{client: c, broker: broker, host: hostname}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no brokers configured")
	}
	return nil, lastErr
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

func (b *AgentBus) Close() { b.client.Disconnect(500) }

// CtrlBus is the controller side of the MQTT transport.
type CtrlBus struct {
	client paho.Client
	broker string
}

// DialController connects to the first reachable broker.
func DialController() (*CtrlBus, error) {
	var lastErr error
	for _, broker := range Brokers {
		id := "rmm-ctrl-" + randHex(3)
		c, err := dial(broker, id, nil)
		if err != nil {
			log.Printf("[mqtt] %s unreachable: %v", broker, shortErr(err))
			lastErr = err
			continue
		}
		log.Printf("[mqtt] controller connected via %s", broker)
		return &CtrlBus{client: c, broker: broker}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no brokers configured")
	}
	return nil, lastErr
}

// Subscribe registers hello + all agent outputs. Topic is passed so the
// controller can route (hello vs out/<host>).
func (b *CtrlBus) Subscribe(handle func(topic string, env relay.Envelope)) error {
	topics := map[string]byte{
		Base + "/hello": 0,
		Base + "/out/+": 0,
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

// PublishCmd sends a directed command to one agent host.
func (b *CtrlBus) PublishCmd(host string, env relay.Envelope) error {
	return publish(b.client, Base+"/cmd/"+host, env)
}

func (b *CtrlBus) Close() { b.client.Disconnect(500) }

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
